### Title
Native ETH Delivery Revert in `finTransfer` Permanently Freezes Bridged Funds — (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

---

### Summary

When a user bridges native ETH from NEAR to EVM and specifies a contract recipient that cannot receive ETH (no `receive`/`fallback`, or one that explicitly reverts), every call to `finTransfer` will revert. Because the nonce mark is also rolled back on revert and there is no refund path on NEAR, the user's locked/burned NEAR tokens are permanently frozen with no recovery mechanism.

---

### Finding Description

`finTransfer` in `OmniBridge.sol` marks the destination nonce as consumed **before** attempting ETH delivery: [1](#0-0) 

```solidity
completedTransfers[payload.destinationNonce] = true;
```

Then, for native ETH transfers (`payload.tokenAddress == address(0)`), it attempts delivery and reverts the entire transaction on failure: [2](#0-1) 

```solidity
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
```

Because `revert FailedToSendEther()` rolls back the entire transaction, `completedTransfers[payload.destinationNonce] = true` is also undone. The nonce is never consumed, so the relayer can retry — but every retry will produce the same revert if the recipient contract cannot accept ETH.

On the NEAR side, the user's tokens were already locked or burned when `ft_transfer_call` was processed by `init_transfer_internal`: [3](#0-2) 

There is no cancel or refund entry point on NEAR that a user can invoke to recover tokens from a pending `TransferMessage` whose EVM finalization is permanently blocked. `remove_transfer_message` is only reachable through privileged internal callbacks, not by the original sender.

---

### Impact Explanation

**Critical — permanent freezing of bridged funds.**

The user's NEAR tokens (locked or burned at transfer initiation) can never be recovered:

- The EVM `finTransfer` will always revert for a recipient that rejects ETH.
- The NEAR bridge has no user-callable cancel/refund path for an initiated transfer.
- The relayer's ETH is returned on revert, but the user's NEAR-side tokens remain permanently locked/burned.

---

### Likelihood Explanation

**Low-to-medium.** Realistic triggering conditions include:

- A user sends native ETH to a smart-contract wallet (e.g., a Gnosis Safe deployment) that does not implement a `receive` function.
- A user sends to a contract that was recently upgraded and had its `receive` function removed.
- A user mistakenly pastes a contract address (e.g., a token contract) as the EVM recipient.

None of these require privileged access; any bridge user can trigger this by specifying a bad EVM recipient in their NEAR-side transfer.

---

### Recommendation

Replace the hard revert on ETH delivery failure with a pull-payment (escrow) pattern:

```solidity
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) {
        // Store for later claim instead of reverting
        pendingWithdrawals[payload.recipient] += payload.amount;
        emit EthDeliveryFailed(payload.recipient, payload.amount, payload.destinationNonce);
    }
}
```

This ensures the nonce is consumed (preventing replay), the ETH is held safely in the contract, and the recipient (or an admin-assisted refund path) can later claim it. Alternatively, add a NEAR-side cancel mechanism that allows users to reclaim tokens when EVM finalization is provably impossible.

---

### Proof of Concept

1. User on NEAR calls `ft_transfer_call` → `init_transfer_internal` → NEAR tokens locked/burned, `TransferMessage` stored.
2. User specifies as EVM recipient a contract `C` with no `receive` function (e.g., a plain ERC-20 token contract address).
3. Relayer calls `finTransfer` on EVM with `msg.value = payload.amount`.
4. Line 287: `completedTransfers[nonce] = true`.
5. Line 319–321: `C.call{value: amount}("")` returns `success = false`.
6. Line 322: `revert FailedToSendEther()` — entire transaction rolls back, including line 287.
7. Relayer retries indefinitely; every attempt reverts identically.
8. User's NEAR tokens remain locked/burned with no recovery path. Funds are permanently frozen.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-287)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L317-322)
```text
        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
```

**File:** near/omni-bridge/src/lib.rs (L1850-1857)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
```
