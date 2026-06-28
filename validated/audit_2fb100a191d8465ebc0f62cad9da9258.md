### Title
Reentrancy in `initTransfer1155` via Malicious ERC1155 Token Causes Nonce Collision and Unauthorized Minting — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`initTransfer1155` increments `currentOriginNonce` before making an external `safeTransferFrom` call, but reads `currentOriginNonce` again at the time of the `emit` statement. A malicious ERC1155 token can re-enter `initTransfer1155` during `safeTransferFrom`, causing `currentOriginNonce` to be incremented a second time. Both the inner and outer calls then emit `InitTransfer` with the same nonce value. The NEAR bridge processes the first event (inner call, no tokens actually locked) and rejects the second as a duplicate, enabling unauthorized minting of bridged tokens on NEAR.

### Finding Description

In `initTransfer1155` (lines 448–489 of `OmniBridge.sol`):

```solidity
function initTransfer1155(...) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
    currentOriginNonce += 1;                          // (1) nonce incremented to N+1
    ...
    IERC1155(tokenAddress).safeTransferFrom(          // (2) external call — re-entry window
        msg.sender, address(this), tokenId, amount, ""
    );
    ...
    emit BridgeTypes.InitTransfer(
        msg.sender, deterministicToken,
        currentOriginNonce,                           // (3) reads CURRENT value, not saved N+1
        amount, fee, nativeFee, recipient, message
    );
}
```

The nonce is saved as a local variable nowhere. If a malicious ERC1155 token's `safeTransferFrom` re-enters `initTransfer1155` before returning:

- **Outer call**: increments nonce to N+1, calls `safeTransferFrom` → re-entry begins
- **Inner call**: increments nonce to N+2, calls `safeTransferFrom` (no-op in malicious token), emits `InitTransfer` with `currentOriginNonce = N+2`
- **Outer call resumes**: emits `InitTransfer` with `currentOriginNonce = N+2` (same value)

Result: nonce N+1 is never emitted; nonce N+2 is emitted twice.

The `onERC1155Received` hook on OmniBridge is declared `view` and cannot block this re-entry path, because the malicious token calls back into `initTransfer1155` directly during `safeTransferFrom`, before (or instead of) invoking `onERC1155Received`. [1](#0-0) 

### Impact Explanation

The NEAR bridge's `fin_transfer_callback` uses `origin_nonce` as part of the `TransferId` and inserts it into `finalised_transfers`, panicking on duplicate insertion:

```rust
require!(
    self.finalised_transfers.insert(transfer_id),
    BridgeError::TransferAlreadyFinalised.as_ref()
);
``` [2](#0-1) 

The NEAR side processes the first N+2 event (inner call — no ERC1155 tokens were actually locked on EVM) and mints bridged tokens to the attacker. The second N+2 event (outer call) is rejected as a duplicate. Nonce N+1 is permanently skipped. The attacker receives minted tokens on NEAR with zero collateral locked on EVM — a direct theft of bridged token supply.

### Likelihood Explanation

The attack requires:
1. Deploying a malicious ERC1155 token (permissionless).
2. Calling `logMetadata1155` (permissionless) to emit a `LogMetadata` event, then submitting a light-client proof to NEAR's `bind_token` to register the token — both steps are open to any user. [3](#0-2) 

3. Calling `initTransfer1155` with the malicious token.

No admin keys, no oracle compromise, and no threshold MPC collusion are required. Any unprivileged EVM user can execute this end-to-end.

### Recommendation

Cache `currentOriginNonce` into a local variable immediately after incrementing it, and use only the local variable in all subsequent reads within the same function call:

```solidity
currentOriginNonce += 1;
uint64 nonce = currentOriginNonce;   // save before any external call
...
IERC1155(tokenAddress).safeTransferFrom(...);
...
initTransferExtension(msg.sender, deterministicToken, nonce, ...);
emit BridgeTypes.InitTransfer(msg.sender, deterministicToken, nonce, ...);
```

Apply the same fix to `initTransfer` for consistency, as it has the identical pattern with `currentOriginNonce` read at emit time after external token calls. [4](#0-3) 

### Proof of Concept

1. Attacker deploys `MaliciousERC1155` whose `safeTransferFrom` re-enters `OmniBridge.initTransfer1155` once (guarded by a depth flag), then returns without transferring any tokens.
2. Attacker calls `OmniBridge.logMetadata1155(maliciousToken, tokenId)` → emits `LogMetadata`.
3. Attacker submits light-client proof of the `LogMetadata` event to NEAR's `bind_token` → token registered with decimals.
4. Attacker calls `OmniBridge.initTransfer1155(maliciousToken, tokenId, amount, 0, 0, "near:attacker.near", "")`.
   - `currentOriginNonce` → N+1.
   - `safeTransferFrom` triggers re-entry:
     - Inner call: `currentOriginNonce` → N+2; `safeTransferFrom` is a no-op; emits `InitTransfer(attacker, deterministicToken, N+2, amount, ...)`.
   - Outer call resumes: emits `InitTransfer(attacker, deterministicToken, N+2, amount, ...)`.
5. NEAR relayer submits proof of the first N+2 event → `fin_transfer_callback` mints `amount` tokens to `attacker.near`. Zero ERC1155 tokens were ever locked on EVM.
6. Second N+2 event proof submission panics with `TransferAlreadyFinalised`. Nonce N+1 is permanently lost.

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L447-490)
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
    }
```

**File:** near/omni-bridge/src/lib.rs (L2228-2231)
```rust
        require!(
            self.finalised_transfers.insert(transfer_id),
            BridgeError::TransferAlreadyFinalised.as_ref()
        );
```
