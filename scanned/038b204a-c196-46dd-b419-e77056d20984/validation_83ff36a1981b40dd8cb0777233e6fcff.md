### Title
Re-entrancy in `initTransfer` / `initTransfer1155` Causes `originNonce` Collision and Permanent Freezing of Bridged Funds — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`initTransfer` and `initTransfer1155` in `OmniBridge.sol` both increment `currentOriginNonce` at the top of the function but then **read `currentOriginNonce` again after an external token-transfer call** when passing it to `initTransferExtension` and `emit InitTransfer`. A malicious ERC-777 token (via `tokensToSend` hook) or a malicious ERC-1155 token (via a crafted `safeTransferFrom` implementation) can re-enter either function during the external call, increment `currentOriginNonce` a second time, and cause the outer call to emit an `InitTransfer` event with the **same `originNonce`** as the inner call. The NEAR side treats `originNonce` as a unique transfer identifier; it processes the first event and permanently ignores the second, locking the outer call's tokens in the EVM bridge with no recovery path.

---

### Finding Description

Both outbound-transfer entry points share the same structural flaw:

**`initTransfer`** [1](#0-0) 

```
currentOriginNonce += 1;          // (1) nonce becomes N
...
IERC20(tokenAddress).safeTransferFrom(   // (2) external call — ERC-777 tokensToSend
    msg.sender, address(this), amount    //     fires on msg.sender here
);
...
initTransferExtension(..., currentOriginNonce, ...);  // (3) reads currentOriginNonce
emit InitTransfer(..., currentOriginNonce, ...);      //     which may now be N+1
```

**`initTransfer1155`** [2](#0-1) 

```
currentOriginNonce += 1;          // (1) nonce becomes N
...
IERC1155(tokenAddress).safeTransferFrom(  // (2) external call — malicious token
    msg.sender, address(this), ...        //     can re-enter before returning
);
...
initTransferExtension(..., currentOriginNonce, ...);  // (3) reads currentOriginNonce
emit InitTransfer(..., currentOriginNonce, ...);      //     which may now be N+1
```

The re-entrant call at step (2) executes steps (1)–(3) for itself, advancing `currentOriginNonce` from N to N+1 and emitting `InitTransfer(originNonce=N+1)`. When control returns to the outer call, it reads the already-advanced `currentOriginNonce = N+1` and emits a second `InitTransfer(originNonce=N+1)`. Nonce N is never emitted; nonce N+1 appears twice.

This directly violates the documented invariant: [3](#0-2) 

> "Every `originNonce` is incremented atomically. A nonce must never be reusable."
> "State before external calls: Always mutate state … before any external call … This is the primary reentrancy defense."

The `onERC1155Received` guard (`operator != address(this)`) does **not** block this attack because in `initTransfer1155` the bridge itself is the caller of `safeTransferFrom`, so `operator == address(this)` passes the check. The malicious token can re-enter `initTransfer1155` directly inside its own `safeTransferFrom` body before invoking `onERC1155Received`. [4](#0-3) 

---

### Impact Explanation

The NEAR `fin_transfer_callback` reconstructs the transfer using `origin_nonce` from the parsed EVM event: [5](#0-4) 

Two `InitTransfer` events with identical `originNonce` are indistinguishable to the NEAR prover. NEAR processes the first and permanently ignores the second. The outer call's tokens are locked inside the EVM bridge contract with no admin-recovery function and no mechanism to re-submit the proof. This constitutes **permanent freezing of bridged funds**, which is in the critical impact scope.

Additionally, nonce N is skipped entirely in the sequence, creating a gap that can confuse off-chain indexers and relayers that rely on sequential nonce ordering.

---

### Likelihood Explanation

The attack requires only:
1. Deploying a malicious ERC-1155 token (no permission needed).
2. Calling the permissionless `logMetadata1155` to register it with the bridge. [6](#0-5) 
3. Calling `initTransfer1155` with the malicious token.

No admin keys, no MPC compromise, no front-running, and no external dependency failure are required. Any unprivileged user can execute this on-chain.

---

### Recommendation

1. **Capture the nonce into a local variable immediately after incrementing it**, before any external call, and use only that local variable in `initTransferExtension` and `emit`:

```solidity
currentOriginNonce += 1;
uint64 nonce = currentOriginNonce;   // snapshot before external calls
...
IERC1155(tokenAddress).safeTransferFrom(...);
...
initTransferExtension(..., nonce, ...);
emit BridgeTypes.InitTransfer(..., nonce, ...);
```

2. Alternatively, add OpenZeppelin's `ReentrancyGuard` (`nonReentrant` modifier) to both `initTransfer` and `initTransfer1155`.

Both fixes should be applied to `initTransfer` and `initTransfer1155` in `OmniBridge.sol`. [7](#0-6) 

---

### Proof of Concept

```
Attacker deploys MaliciousERC1155 whose safeTransferFrom:
  - on first call: re-enters initTransfer1155 (inner call)
  - on second call (inner): transfers tokens normally and returns

State trace:
  currentOriginNonce = 5 (before attack)

Outer call: initTransfer1155(MaliciousERC1155, ...)
  (1) currentOriginNonce = 6
  (2) MaliciousERC1155.safeTransferFrom → re-enters initTransfer1155
        Inner call:
          (1) currentOriginNonce = 7
          (2) MaliciousERC1155.safeTransferFrom → transfers normally
          (3) initTransferExtension(..., nonce=7, ...)
          (4) emit InitTransfer(originNonce=7)   ← INNER event
        returns
  (3) initTransferExtension(..., currentOriginNonce=7, ...)  ← reads 7, not 6!
  (4) emit InitTransfer(originNonce=7)   ← OUTER event, SAME nonce

Result:
  - originNonce 6 is never emitted → gap in sequence
  - originNonce 7 emitted twice → NEAR processes first, ignores second
  - Outer call's tokens locked in bridge permanently
``` [8](#0-7) [9](#0-8)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-490)
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

**File:** evm/CLAUDE.md (L32-34)
```markdown
- **No replay attacks**: Every `destinationNonce` must be checked against `completedTransfers` and marked used before any token transfer. Every `originNonce` is incremented atomically. A nonce must never be reusable
- **Event completeness**: `InitTransfer` and `FinTransfer` events must contain every field needed to reconstruct the transfer. The NEAR side relies solely on these events — any missing or ambiguous field means lost funds or spoofable transfers. Fields must not be collapsible (e.g. two different transfers must never produce the same event data)
- **State before external calls**: Always mutate state (e.g. mark nonce used) before any external call (token transfer, ETH send, custom minter). This is the primary reentrancy defense
```

**File:** near/omni-bridge/src/lib.rs (L720-732)
```rust
        let destination_nonce =
            self.get_next_destination_nonce(init_transfer.recipient.get_chain());
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
            fee: Self::denormalize_fee(&init_transfer.fee, decimals),
            sender: init_transfer.sender,
            msg: init_transfer.msg,
            destination_nonce,
            origin_transfer_id: None,
        };
```
