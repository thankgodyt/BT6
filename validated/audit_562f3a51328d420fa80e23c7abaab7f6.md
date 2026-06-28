### Title
`fin_transfer_send_tokens_callback` Ignores `ft_transfer` Failure for Native Tokens, Permanently Freezing Bridged Funds — (`near/omni-bridge/src/lib.rs`)

---

### Summary

When finalizing an inbound transfer to a NEAR recipient with no message (`msg` is empty), the bridge uses a plain `ft_transfer` call. If that call fails — for example because the recipient is blacklisted by a USDC-style NEP-141 token — the callback `fin_transfer_send_tokens_callback` takes no recovery action. The transfer is already recorded in `finalised_transfers` and cannot be retried. The native tokens remain permanently locked inside the bridge contract with no admin escape hatch.

---

### Finding Description

`process_fin_transfer_to_near` dispatches `send_tokens`, which for native (non-deployed) tokens with an empty message issues a plain `ft_transfer`: [1](#0-0) 

The result of that call is chained into `fin_transfer_send_tokens_callback` with `is_ft_transfer_call = !msg.is_empty()`. When `msg` is empty, `is_ft_transfer_call` is `false`. [2](#0-1) 

Inside the callback, recovery is gated entirely on `is_refund_required`: [3](#0-2) 

For the `ft_transfer` path (`is_ft_transfer_call = false`) the function unconditionally returns `false` — it never inspects the promise result. If `ft_transfer` panicked (e.g., the token contract rejected the transfer because the recipient is on a blacklist), the callback branch at line 1702 is never entered: [4](#0-3) 

The recovery branch would have called `remove_fin_transfer` and `revert_lock_actions`. Because it is skipped, the transfer ID stays in `finalised_transfers` (preventing any retry), and the native tokens remain locked in the bridge contract with no path to release them.

The transfer is marked finalised before `send_tokens` is even dispatched: [5](#0-4) 

NEAR's cross-contract call model commits the bridge's state changes (including `add_fin_transfer`) in the scheduling receipt; only the token contract's receipt is reverted on failure. The bridge therefore ends up in a state where the transfer is finalised but the tokens were never delivered.

There is no admin function anywhere in the contract to forcibly remove a finalised transfer or redirect tokens to an alternative recipient.

---

### Impact Explanation

Native tokens (e.g., USDC deployed as a NEP-141 token with a blacklist, or any token whose `ft_transfer` can revert) that are locked in the bridge on behalf of an inbound transfer become permanently irrecoverable when the recipient cannot accept them. The transfer ID is consumed from `finalised_transfers`, so the proof cannot be replayed. The tokens sit in the bridge contract forever. This satisfies the Critical impact category: **permanent freezing of bridged funds**.

---

### Likelihood Explanation

Circle's native USDC on NEAR implements a blacklist. Any user whose NEAR address is added to that blacklist after initiating a cross-chain transfer (or who is already on it when a relayer finalizes) triggers this path. The relayer has no way to substitute a different recipient because the recipient is embedded in the verified proof. The condition is reachable by any unprivileged bridge user whose address is blacklisted by a supported token.

---

### Recommendation

1. **Check the promise result for `ft_transfer` as well.** Extend `is_refund_required` (or add a parallel check in the callback) to inspect `env::promise_result_checked(0, …)` even when `is_ft_transfer_call` is `false`. If the promise failed, execute the same recovery path: call `remove_fin_transfer`, `revert_lock_actions`, and emit `FailedFinTransferEvent`.

2. **Add a `receiver` field to `TransferMessage`** (analogous to the external report's recommendation) so that a relayer or the user can supply an alternative delivery address without invalidating the proof of the original transfer.

3. **Add an admin escape hatch** to forcibly remove a stuck finalised transfer and return the locked tokens to a designated address, as a last-resort recovery mechanism.

---

### Proof of Concept

1. Alice initiates a transfer of native USDC (NEP-141, blacklist-enabled) from Ethereum to her NEAR account `alice.near`.
2. Before the relayer finalizes, Circle blacklists `alice.near`.
3. Relayer calls `fin_transfer` on NEAR. `process_fin_transfer_to_near` runs:
   - `add_fin_transfer` records the transfer ID in `finalised_transfers`. [5](#0-4) 
   - `send_tokens` dispatches `ft_transfer(alice.near, amount, None)`. [6](#0-5) 
4. USDC's `ft_transfer` panics because `alice.near` is blacklisted. The promise result is `Failed`.
5. `fin_transfer_send_tokens_callback` is called with `is_ft_transfer_call = false`.
6. `is_refund_required(false)` returns `false` unconditionally. [7](#0-6) 
7. The callback logs `FinTransferEvent` as if the transfer succeeded. No `remove_fin_transfer` or `revert_lock_actions` is called. [8](#0-7) 
8. Alice's USDC is permanently locked in the bridge. The transfer ID is consumed. No retry is possible.

### Citations

**File:** near/omni-bridge/src/lib.rs (L1700-1718)
```rust
        let token = self.get_token_id(&transfer_message.token);

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

**File:** near/omni-bridge/src/lib.rs (L1719-1746)
```rust
        } else {
            // Send fee to the fee recipient
            if transfer_message.fee.fee.0 > 0 {
                if self.is_deployed_token(&token) {
                    ext_token::ext(token)
                        .with_static_gas(MINT_TOKEN_GAS)
                        .mint(fee_recipient.clone(), transfer_message.fee.fee, None)
                        .detach();
                } else {
                    ext_token::ext(token)
                        .with_attached_deposit(ONE_YOCTO)
                        .with_static_gas(FT_TRANSFER_GAS)
                        .ft_transfer(fee_recipient.clone(), transfer_message.fee.fee, None)
                        .detach();
                }
            }

            if transfer_message.fee.native_fee.0 > 0 {
                let native_token_id = self.get_native_token_id(transfer_message.get_origin_chain());

                ext_token::ext(native_token_id)
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
                    .detach();
            }

            env::log_str(&OmniBridgeEvent::FinTransferEvent { transfer_message }.to_log_string());
        }
```

**File:** near/omni-bridge/src/lib.rs (L1783-1803)
```rust
impl Contract {
    fn is_refund_required(is_ft_transfer_call: bool) -> bool {
        if is_ft_transfer_call {
            match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
                Ok(value) => {
                    if let Ok(amount) = near_sdk::serde_json::from_slice::<U128>(&value) {
                        // Normal case: refund if the used token amount is zero
                        // The amount can be zero if the `ft_on_transfer` in the receiver contract returns an amount instead of `0`, or if it panics.
                        amount.0 == 0
                    } else {
                        // Unexpected case: don't refund
                        false
                    }
                }
                // Unexpected case: don't refund
                Err(_) => false,
            }
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

**File:** near/omni-bridge/src/lib.rs (L2102-2107)
```rust
        } else if msg.is_empty() {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
        } else {
```
