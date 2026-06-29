### Title
Reentrancy in `initTransfer1155` via Malicious ERC1155 Token Enables Unauthorized Minting on NEAR — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initTransfer1155` increments `currentOriginNonce` at the top of the function but reads the storage variable **again** after the external `IERC1155.safeTransferFrom` call to populate the emitted `InitTransfer` event. A malicious ERC1155 token can reenter `initTransfer1155` during `safeTransferFrom`, causing the outer call to emit an `InitTransfer` event with the same nonce as the inner call. The inner call can emit a valid-looking event without actually locking any tokens, enabling unauthorized minting on NEAR.

---

### Finding Description

`initTransfer1155` follows this sequence:

```
currentOriginNonce += 1;                          // (1) nonce becomes N
...
IERC1155(tokenAddress).safeTransferFrom(...);     // (2) external call — reentrancy window
...
initTransferExtension(..., currentOriginNonce, ...); // (3) reads storage AFTER external call
emit InitTransfer(..., currentOriginNonce, ...);     // (4) reads storage AFTER external call
``` [1](#0-0) 

Because `currentOriginNonce` is a **storage variable read at steps (3) and (4) after the external call at step (2)**, any reentrant modification of `currentOriginNonce` during step (2) is reflected in the event emitted by the outer call.

**Attack path:**

1. Attacker deploys `MaliciousERC1155` whose `safeTransferFrom` implementation reenters `initTransfer1155` once and then returns `true` without actually transferring tokens or calling `onERC1155Received`.
2. Attacker calls `logMetadata1155(MaliciousERC1155, tokenId)` — this function is **permissionless**. [2](#0-1) 

3. NEAR side processes the `LogMetadata` event and registers the token.
4. Attacker calls `initTransfer1155(MaliciousERC1155, tokenId, amount, ...)`:
   - `currentOriginNonce` becomes **N**.
   - `MaliciousERC1155.safeTransferFrom` is called. Inside, the malicious token reenters `initTransfer1155`:
     - **Inner call**: `currentOriginNonce` becomes **N+1**. The malicious token's inner `safeTransferFrom` returns `true` without transferring tokens. The inner call emits `InitTransfer` with nonce **N+1** — **no tokens locked**.
   - Outer `safeTransferFrom` returns `true` without transferring tokens.
   - Outer call reads `currentOriginNonce` = **N+1** (overwritten by inner call).
   - Outer call emits `InitTransfer` with nonce **N+1** — **duplicate**.
5. NEAR side sees two `InitTransfer` events with nonce N+1. It processes the first (inner call's event) and mints tokens to the attacker. It rejects the second as a replay.
6. Nonce N is never emitted. No tokens were locked on EVM for either event.

The `onERC1155Received` guard (`operator != address(this)`) is not a mitigation: the malicious token's `safeTransferFrom` can skip calling `onERC1155Received` entirely and still return the success selector. [3](#0-2) 

The same root cause exists in `initTransfer` for ERC20 tokens: `currentOriginNonce` is also read after the external `safeTransferFrom` call there. [4](#0-3) 

The contract imports no `ReentrancyGuardUpgradeable` and applies no `nonReentrant` modifier to any transfer-initiating function.

The security invariant documented in `evm/CLAUDE.md` — *"State before external calls: Always mutate state before any external call"* — is violated here because the nonce is **incremented** before the external call but **read** after it. [5](#0-4) 

---

### Impact Explanation

An unprivileged attacker can mint an arbitrary quantity of bridged tokens on NEAR without locking any corresponding tokens on the EVM side. This breaks the lock/mint invariant of the bridge, constitutes unauthorized minting, and directly inflates the NEAR-side token supply while the EVM-side escrow holds nothing. This is a critical loss-of-funds / balance-manipulation impact.

---

### Likelihood Explanation

The entry path requires only:
- Deploying a malicious ERC1155 contract (no special permissions).
- Calling the permissionless `logMetadata1155` to register it.
- Calling `initTransfer1155` with the malicious token.

No admin compromise, no MPC collusion, and no front-running is required. Any unprivileged bridge user can execute this attack.

---

### Recommendation

1. **Capture the nonce in a local variable before any external call** and use that local variable in `initTransferExtension` and `emit`:

```solidity
function initTransfer1155(...) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
    currentOriginNonce += 1;
    uint64 nonce = currentOriginNonce; // capture before external call
    ...
    IERC1155(tokenAddress).safeTransferFrom(...);
    ...
    initTransferExtension(..., nonce, ...);
    emit BridgeTypes.InitTransfer(..., nonce, ...);
}
```

Apply the same fix to `initTransfer`.

2. **Add `ReentrancyGuardUpgradeable` and the `nonReentrant` modifier** to `initTransfer`, `initTransfer1155`, and `finTransfer` as defense-in-depth.

---

### Proof of Concept

```solidity
contract MaliciousERC1155 is ERC1155 {
    OmniBridge bridge;
    bool reentered;

    function safeTransferFrom(
        address from, address to, uint256 id, uint256 amount, bytes memory
    ) public override {
        if (!reentered) {
            reentered = true;
            // Reenter: inner call increments nonce to N+1, emits InitTransfer(N+1) with no tokens locked
            bridge.initTransfer1155(address(this), id, amount, 0, 0, "attacker.near", "");
            reentered = false;
        }
        //

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-437)
```text
    function initTransfer(
        address tokenAddress,
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

        uint256 extensionValue;
        if (tokenAddress == address(0)) {
            if (fee != 0) {
                revert InvalidFee();
            }
            extensionValue = msg.value - amount - nativeFee;
        } else {
            extensionValue = msg.value - nativeFee;
            if (customMinters[tokenAddress] != address(0)) {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    customMinters[tokenAddress],
                    amount
                );
                ICustomMinter(customMinters[tokenAddress]).burn(
                    tokenAddress,
                    amount
                );
            } else if (isBridgeToken[tokenAddress]) {
                BridgeToken(tokenAddress).burn(msg.sender, amount);
            } else {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
            }
        }

        initTransferExtension(
            msg.sender,
            tokenAddress,
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
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message
        );
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L447-489)
```text
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

**File:** evm/CLAUDE.md (L34-34)
```markdown
- **State before external calls**: Always mutate state (e.g. mark nonce used) before any external call (token transfer, ETH send, custom minter). This is the primary reentrancy defense
```
