### Title
Reentrancy in `initTransfer` via ERC777/callback tokens causes nonce collision and permanent fund loss - (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`OmniBridge.initTransfer` increments `currentOriginNonce` at the top of the function but reads it again *after* the external token call to populate `initTransferExtension` and the `InitTransfer` event. A token with a send/transfer callback (e.g., ERC777's `tokensToSend` hook) can reenter `initTransfer` during the external call, causing the inner call to increment `currentOriginNonce` a second time. Both the inner and outer calls then emit `InitTransfer` events with the same nonce, while the outer transfer's correct nonce is never emitted. The NEAR side treats any emitted event as proof of locked funds and will reject the duplicate nonce as a replay, permanently locking the outer transfer's tokens on EVM with no corresponding NEAR-side finalization possible.

### Finding Description

In `OmniBridge.initTransfer`, the execution order is:

1. `currentOriginNonce += 1` — nonce incremented to N
2. External call: `IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount)` — attacker's ERC777 `tokensToSend` hook fires here
3. Inside the hook, attacker reenters `initTransfer`:
   - `currentOriginNonce += 1` — nonce incremented to N+1
   - Inner token transfer completes (no further callback)
   - `initTransferExtension(..., currentOriginNonce=N+1, ...)`
   - `emit InitTransfer(..., currentOriginNonce=N+1, ...)` — inner event emitted with nonce N+1
4. Outer call resumes after the external call returns
5. `initTransferExtension(..., currentOriginNonce=N+1, ...)` — reads the *current* storage value, which is now N+1
6. `emit InitTransfer(..., currentOriginNonce=N+1, ...)` — outer event also emitted with nonce N+1 [1](#0-0) 

The contract has no `ReentrancyGuardUpgradeable` and no `nonReentrant` modifier on `initTransfer`. The CLAUDE.md security invariant "State before external calls" is only partially satisfied: the nonce is incremented before the external call, but it is *read again* after the external call for event emission and extension, breaking the invariant under reentrancy. [2](#0-1) 

The same structural flaw exists in `initTransfer1155`, which also increments `currentOriginNonce` at the top and reads it again after `IERC1155.safeTransferFrom`. [3](#0-2) 

### Impact Explanation

- **Nonce N** (the outer call's intended nonce) is never emitted in any `InitTransfer` event. The outer transfer's tokens are burned/locked on EVM with no corresponding event the NEAR side can process.
- **Nonce N+1** is emitted twice — once by the inner call and once by the outer call. The NEAR side processes the first occurrence and rejects the second as a replay (`ERR_TRANSFER_ALREADY_FINALISED` or equivalent).
- The outer transfer's tokens are **permanently locked** in the bridge contract with no recovery path, since the NEAR side will never finalize a transfer for nonce N (no event exists) and will reject nonce N+1 as a duplicate.
- This constitutes permanent loss of bridged funds triggered by an unprivileged user supplying a callback-capable token.

### Likelihood Explanation

ERC777 tokens are backward-compatible with ERC20 and are deployed on Ethereum mainnet (e.g., imBTC, LUKSO LYX). The `initTransfer` non-bridge path accepts any ERC20 token. An attacker can:
1. Deploy or use an existing ERC777 token
2. Register as the `tokensToSend` operator/hook implementer for their own address
3. Call `initTransfer` with that token; the hook fires during `safeTransferFrom` and reenters `initTransfer` with a second transfer

No admin privileges are required. The bridge is explicitly permissionless for `initTransfer`.

### Recommendation

1. **Snapshot the nonce before external calls** and use the snapshot value in `initTransferExtension` and `emit`:
   ```solidity
   uint64 originNonce = currentOriginNonce + 1;
   currentOriginNonce = originNonce;
   // ... external calls ...
   initTransferExtension(..., originNonce, ...);
   emit BridgeTypes.InitTransfer(..., originNonce, ...);
   ```
2. **Add `ReentrancyGuardUpgradeable`** and apply `nonReentrant` to `initTransfer` and `initTransfer1155`.
3. Apply the same fix to `initTransfer1155`.

### Proof of Concept

```
State: currentOriginNonce = 5

1. Attacker calls initTransfer(erc777Token, amount1, ...)
   → currentOriginNonce = 6
   → safeTransferFrom fires tokensToSend hook on attacker

2. Attacker's hook calls initTransfer(erc777Token, amount2, ...)
   → currentOriginNonce = 7
   → safeTransferFrom (no hook this time)
   → initTransferExtension(..., nonce=7, ...)
   → emit InitTransfer(nonce=7, amount=amount2)   ← inner event

3. Outer call resumes
   → initTransferExtension(..., nonce=7, ...)     ← reads currentOriginNonce=7
   → emit InitTransfer(nonce=7, amount=amount1)   ← outer event, SAME nonce

Result:
- Two InitTransfer events with nonce 7 on EVM
- Nonce 6 never emitted → amount1 tokens permanently locked
- NEAR processes nonce 7 once (amount2), rejects second nonce 7 as replay
``` [4](#0-3) [5](#0-4)

### Citations

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

**File:** evm/CLAUDE.md (L32-36)
```markdown
- **No replay attacks**: Every `destinationNonce` must be checked against `completedTransfers` and marked used before any token transfer. Every `originNonce` is incremented atomically. A nonce must never be reusable
- **Event completeness**: `InitTransfer` and `FinTransfer` events must contain every field needed to reconstruct the transfer. The NEAR side relies solely on these events — any missing or ambiguous field means lost funds or spoofable transfers. Fields must not be collapsible (e.g. two different transfers must never produce the same event data)
- **State before external calls**: Always mutate state (e.g. mark nonce used) before any external call (token transfer, ETH send, custom minter). This is the primary reentrancy defense
- **No token release without signature**: Never mint, transfer, or unlock tokens to a recipient without first verifying a valid MPC signature. No admin function, emergency path, or refactor may bypass this — it is the only authorization gate for finTransfer
- **Event–transfer atomicity**: `InitTransfer` must only be emitted in a code path where tokens have already been burned/locked in the same transaction. If the token transfer reverts or is skipped, the event must not emit — the NEAR side will treat any emitted event as proof that tokens are held
```
