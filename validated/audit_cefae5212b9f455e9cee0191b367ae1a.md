Audit Report

## Title
`fin_transfer_send_tokens_callback` Silently Ignores `ft_transfer` Failure, Permanently Freezing Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

## Summary
`is_refund_required` unconditionally returns `false` when `is_ft_transfer_call` is `false`, meaning a failed plain `ft_transfer` (dispatched when `msg` is empty for non-deployed tokens) is treated as success. The callback emits `FinTransferEvent` and pays the relayer fee even though the recipient received nothing. Because `add_fin_transfer` and `unlock_tokens_if_needed` committed their state mutations in an earlier receipt, the transfer ID is permanently recorded in `finalised_transfers` and `locked_tokens` is already decremented, leaving the user's funds irretrievably frozen with no re-submission path.

## Finding Description

**Root cause — `is_refund_required` is blind to plain `ft_transfer` failures:** [1](#0-0) 

When `is_ft_transfer_call` is `false`, the function skips the promise-result check entirely and returns `false` (line 1800–1802). No inspection of `env::promise_result_checked` occurs for the plain `ft_transfer` path.

**`send_tokens` dispatches a plain `ft_transfer` for non-deployed tokens with an empty `msg`:** [2](#0-1) 

**The callback is scheduled with `is_ft_transfer_call = !msg.is_empty()`**, which evaluates to `false` when `msg` is empty: [3](#0-2) 

**State mutations commit before the token send.** `add_fin_transfer` inserts the transfer ID into `finalised_transfers` and `unlock_tokens_if_needed` decrements `locked_tokens` — both in the same receipt as `process_fin_transfer_to_near`, which has already committed by the time the callback fires: [4](#0-3) 

**The callback takes the success branch on failure.** Because `is_refund_required` returns `false`, the `else` branch executes: the relayer fee is paid and `FinTransferEvent` is emitted. The correct recovery path (`burn_tokens_if_needed`, `revert_lock_actions`, `remove_fin_transfer`, `FailedFinTransferEvent`) is never taken: [5](#0-4) 

The same structural defect exists in `resolve_fast_transfer` and `resolve_utxo_fin_transfer`, which share the same `is_refund_required` helper: [6](#0-5) [7](#0-6) 

## Impact Explanation

This is a **permanent freezing of bridged funds**, matching the Critical allowed impact scope. For any non-deployed (locked) NEAR token whose contract can reject `ft_transfer` — USDC-style blacklist, paused token, or custom rejection logic — the following permanent state results:

1. The origin-chain proof is consumed; `finalised_transfers` blocks any re-submission.
2. `locked_tokens` is decremented, breaking the bridge's internal accounting.
3. The recipient receives nothing; tokens remain stranded in the bridge contract.
4. The relayer collects its fee for a delivery that never occurred.

There is no recovery path for the user.

## Likelihood Explanation

USDC and USDC.e are among the most commonly bridged assets. Circle actively maintains a blacklist. A user whose NEAR address is blacklisted after initiating a bridge transfer — or who specifies a blacklisted address — triggers this path with no warning and no recourse. The code path is reached on every standard (no-`msg`) inbound `fin_transfer` for a non-deployed token, making it a realistic production scenario requiring no special attacker capability.

## Recommendation

In `fin_transfer_send_tokens_callback` (and analogously in `resolve_fast_transfer` / `resolve_utxo_fin_transfer`), check the promise result unconditionally, not only when `is_ft_transfer_call` is `true`. Extend `is_refund_required` (or add a separate check) to call `env::promise_result_checked(0, …)` for the plain `ft_transfer` case and treat a failed promise as requiring a refund: revert lock actions, remove the finalized-transfer record, and emit `FailedFinTransferEvent` instead of `FinTransferEvent`.

## Proof of Concept

1. Deploy a NEAR token contract that rejects `ft_transfer` to a specific address (simulating a USDC blacklist). Register it with the bridge as a non-deployed (locked) token.
2. Lock tokens in the EVM bridge and submit a valid `fin_transfer` proof to the NEAR bridge targeting the blacklisted NEAR address with an empty `msg`.
3. Observe that `fin_transfer_callback` → `process_fin_transfer_to_near` → `add_fin_transfer` commits the transfer to `finalised_transfers` and `unlock_tokens_if_needed` decrements `locked_tokens`.
4. The `ft_transfer` to the blacklisted address panics; `fin_transfer_send_tokens_callback` is invoked with `is_ft_transfer_call = false`.
5. `is_refund_required(false)` returns `false`; the callback emits `FinTransferEvent` and pays the relayer fee.
6. Confirm: recipient balance is zero, `finalised_transfers` contains the transfer ID (preventing retry), `locked_tokens` is decremented, and the tokens remain in the bridge contract — permanently frozen.

### Citations

**File:** near/omni-bridge/src/lib.rs (L906-911)
```rust
        if Self::is_refund_required(is_ft_transfer_call) {
            self.remove_fast_transfer(fast_transfer_id);
            amount
        } else {
            U128(0)
        }
```

**File:** near/omni-bridge/src/lib.rs (L1024-1025)
```rust
        let is_ft_transfer_call = !utxo_fin_transfer_msg.msg.is_empty();
        if Self::is_refund_required(is_ft_transfer_call) {
```

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

**File:** near/omni-bridge/src/lib.rs (L1784-1803)
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
            // Not ft_transfer_call: don't refund
            false
        }
```

**File:** near/omni-bridge/src/lib.rs (L1875-1885)
```rust
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());

        let token = self.get_token_id(&transfer_message.token);
        let fast_transfer = FastTransfer::from_transfer(transfer_message.clone(), token.clone());
        let fast_transfer_status = self.get_fast_transfer_status(&fast_transfer.id());

        let lock_actions = vec![self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        )];
```

**File:** near/omni-bridge/src/lib.rs (L1967-1977)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L2102-2106)
```rust
        } else if msg.is_empty() {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
```
