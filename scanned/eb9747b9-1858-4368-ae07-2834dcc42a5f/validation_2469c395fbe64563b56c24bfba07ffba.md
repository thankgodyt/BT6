### Title
`ft_transfer_call` Failure Treated as Success in Callback, Permanently Freezing Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

### Summary

In `fin_transfer_send_tokens_callback` and `resolve_fast_transfer`, when a `ft_transfer_call` to the recipient fails with a promise error (`Err`), the helper `is_refund_required` returns `false` — treating the failure as a success. The bridge neither burns the minted tokens nor returns the locked tokens, while the transfer is already marked as finalized. This permanently freezes the user's bridged funds inside the bridge contract with no recovery path.

### Finding Description

The `is_refund_required` function determines whether tokens should be returned after a failed delivery: [1](#0-0) 

When `is_ft_transfer_call` is `true` and the promise result is `Err` (i.e., the `ft_transfer_call` panicked or failed), the function returns `false` — the "Unexpected case: don't refund" branch. This return value is consumed by both `fin_transfer_send_tokens_callback` and `resolve_fast_transfer`.

In `fin_transfer_send_tokens_callback`, a `false` return from `is_refund_required` causes the code to skip the burn/revert path and instead log a `FinTransferEvent` as if the transfer succeeded: [2](#0-1) 

The correct rollback path — burning minted tokens and reverting lock actions — is only taken when `is_refund_required` returns `true`: [3](#0-2) 

The same flaw exists in `resolve_fast_transfer`: [4](#0-3) 

In NEAR's `ft_transfer_call` protocol, when the recipient's `ft_on_transfer` panics, the token contract atomically reverts the transfer — tokens return to the bridge's account. However, the bridge's callback incorrectly treats this reversion as a successful delivery, taking no corrective action. The transfer is already recorded in `finalised_transfers` before the token send, preventing any replay. The tokens are permanently stranded in the bridge contract.

The `revert_lock_actions` mechanism exists precisely to handle this scenario: [5](#0-4) 

But it is never invoked when `ft_transfer_call` returns `Err`.

### Impact Explanation

For inbound transfers (Foreign → NEAR) where the recipient specifies a `msg` field:
- **Deployed/bridged tokens**: The bridge mints tokens to itself, calls `ft_transfer_call`. If the call fails, minted tokens remain in the bridge with no burn triggered. Supply is inflated and user funds are lost.
- **Native NEAR tokens**: The bridge holds locked tokens and calls `ft_transfer_call`. If the call fails, tokens remain locked in the bridge with no unlock or refund triggered.

In both cases the transfer is finalized (replay-protected), the `FinTransferEvent` is emitted signaling success, and there is no admin or user-callable function to recover the stranded tokens. This constitutes permanent, irrecoverable loss of bridged funds.

### Likelihood Explanation

The `msg` field is user-supplied and triggers `ft_transfer_call` instead of `ft_transfer`. Any of the following realistic conditions cause `ft_transfer_call` to return `Err`:
1. The recipient contract's `ft_on_transfer` panics (e.g., due to a bug, unexpected input, or deliberate design).
2. The recipient contract does not implement `ft_on_transfer`.
3. Gas exhaustion in the recipient's callback.

A malicious actor can deploy a recipient contract that always panics in `ft_on_transfer`, then convince users to bridge tokens to it, permanently destroying those funds. Even without malice, any legitimate contract bug in the recipient triggers the same outcome.

### Recommendation

In `is_refund_required`, treat a failed `ft_transfer_call` promise (`Err`) as requiring a refund, not as a success:

```rust
// Unexpected case: DO refund — tokens were returned to bridge by the token contract
Err(_) => true,
```

This ensures that when `ft_transfer_call` fails, `fin_transfer_send_tokens_callback` and `resolve_fast_transfer` both enter the rollback path: burning minted tokens, reverting lock actions, removing the finalization record, and emitting `FailedFinTransferEvent`. The transfer can then be retried or the user refunded.

### Proof of Concept

1. User bridges token X from Ethereum to NEAR, specifying a `msg` field targeting a recipient contract `R`.
2. Relayer calls `fin_transfer` with a valid proof; `fin_transfer_callback` processes it and calls `process_fin_transfer_to_near`.
3. The bridge mints/unlocks tokens and calls `ft_transfer_call` on token X with recipient `R` and the user's `msg`.
4. `R.ft_on_transfer` panics. The token contract reverts the transfer; tokens return to the bridge.
5. `fin_transfer_send_tokens_callback` is invoked. `is_refund_required(true)` reads the promise result as `Err` and returns `false`.
6. The callback skips the burn/revert branch, logs `FinTransferEvent`, and returns.
7. The transfer ID is in `finalised_transfers`; no retry is possible. Tokens are permanently locked in the bridge with no recovery path. [1](#0-0)

### Citations

**File:** near/omni-bridge/src/lib.rs (L1700-1746)
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

**File:** near/omni-bridge/src/lib.rs (L1784-1800)
```rust
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
```

**File:** near/omni-bridge/src/lib.rs (L1906-1912)
```rust
            Self::check_storage_balance_result(
                (storage_deposit_action_index + 1)
                    .try_into()
                    .near_expect(BridgeError::Cast)
            ) && storage_deposit_actions[storage_deposit_action_index].account_id == recipient
                && storage_deposit_actions[storage_deposit_action_index].token_id == token,
            BridgeError::StorageRecipientOmitted.as_ref()
```

**File:** near/omni-bridge/src/token_lock.rs (L122-142)
```rust
    pub fn revert_lock_actions(&mut self, lock_actions: &[LockAction]) {
        for lock_action in lock_actions {
            match lock_action {
                LockAction::Locked {
                    chain_kind,
                    token_id,
                    amount,
                } => {
                    self.unlock_tokens(*chain_kind, token_id, *amount);
                }
                LockAction::Unlocked {
                    chain_kind,
                    token_id,
                    amount,
                } => {
                    self.lock_tokens(*chain_kind, token_id, *amount);
                }
                LockAction::Unchanged => {}
            }
        }
    }
```
