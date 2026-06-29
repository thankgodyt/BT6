### Title
Permanent Loss of Bridged Funds When Token Transfer Fails Without Message in `fin_transfer_send_tokens_callback` — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

When a cross-chain transfer is finalized on NEAR with no message payload, the `fin_transfer_send_tokens_callback` function unconditionally treats the outcome as a success, regardless of whether the underlying token transfer (`mint` or `ft_transfer`) actually succeeded. If the token transfer fails, the transfer is permanently marked as finalized, the source-chain tokens are already burned/locked and irrecoverable, and the recipient never receives their tokens.

---

### Finding Description

The NEAR bridge finalizes inbound transfers (EVM/Solana/Starknet → NEAR) through a two-step callback chain:

**Step 1 — `fin_transfer_callback` → `process_fin_transfer_to_near`**

Inside `process_fin_transfer_to_near`, the transfer is immediately and permanently recorded as finalized via `add_fin_transfer` before the token transfer is attempted: [1](#0-0) 

Then `send_tokens` is dispatched and `fin_transfer_send_tokens_callback` is chained as its callback, with `is_ft_transfer_call` set to `!msg.is_empty()`: [2](#0-1) 

**Step 2 — `fin_transfer_send_tokens_callback`**

The callback delegates the refund decision entirely to `is_refund_required`: [3](#0-2) 

**Root cause — `is_refund_required` when `is_ft_transfer_call = false`**

When the transfer carries no message, `is_ft_transfer_call` is `false`. `is_refund_required` then returns `false` unconditionally, **without ever reading the promise result**: [4](#0-3) 

This means that if `mint` (for deployed bridge tokens) or `ft_transfer` (for native tokens) fails, the callback takes the "success" branch, emits `FinTransferEvent`, and optionally pays fees — all without detecting the failure. The `remove_fin_transfer` call that would un-finalize the transfer is never reached: [5](#0-4) 

---

### Impact Explanation

- The source-chain tokens (EVM/Solana/Starknet) are already burned or locked at `initTrans

### Citations

**File:** near/omni-bridge/src/lib.rs (L1702-1718)
```rust
        if Self::is_refund_required(is_ft_transfer_call) {
            self.burn_tokens_if_needed(
                token.clone(),
                U128(
                    transfer_message
                        .amount_without_fee()
                        .near_expect(BridgeError::InvalidFee),
                ),
            );

            self.revert_lock_actions(&lock_actions);

            self.remove_fin_transfer(&transfer_message.get_transfer_id(), storage_owner);

            env::log_str(
                &OmniBridgeEvent::FailedFinTransferEvent { transfer_message }.to_log_string(),
            );
```

**File:** near/omni-bridge/src/lib.rs (L1800-1803)
```rust
        } else {
            // Not ft_transfer_call: don't refund
            false
        }
```

**File:** near/omni-bridge/src/lib.rs (L1875-1875)
```rust
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());
```

**File:** near/omni-bridge/src/lib.rs (L1957-1977)
```rust
        self.send_tokens(
            token.clone(),
            recipient,
            U128(
                transfer_message
                    .amount_without_fee()
                    .near_expect(BridgeError::InvalidFee),
            ),
            &msg,
        )
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(SEND_TOKENS_CALLBACK_GAS)
                .fin_transfer_send_tokens_callback(
                    transfer_message,
                    &fee_recipient,
                    !msg.is_empty(),
                    predecessor_account_id,
                    lock_actions,
                ),
        )
```
