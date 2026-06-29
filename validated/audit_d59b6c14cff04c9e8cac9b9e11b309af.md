Audit Report

## Title
Silent `ft_transfer` Failure Permanently Freezes Bridged Funds on NEAR — (File: near/omni-bridge/src/lib.rs)

## Summary

When `fin_transfer` finalizes an inbound transfer to a native NEP-141 token recipient with an empty `msg`, the transfer nonce is permanently inserted into `finalised_transfers` before the async `ft_transfer` cross-contract call. If that `ft_transfer` fails (e.g., token paused), the callback `fin_transfer_send_tokens_callback` unconditionally treats the outcome as success because `is_refund_required(false)` returns `false` without inspecting the promise result. The nonce is never removed, the source-chain funds are already locked or burned, and no on-chain recovery path exists.

## Finding Description

**Step 1 — Nonce permanently consumed before async call.**
`process_fin_transfer_to_near` calls `add_fin_transfer` synchronously, inserting the `TransferId` into `finalised_transfers` and panicking if already present. [1](#0-0) [2](#0-1) 

**Step 2 — `ft_transfer` dispatched with `is_ft_transfer_call = false`.**
When `msg` is empty and the token is neither wNEAR nor a deployed bridge token, `send_tokens` dispatches a plain `ft_transfer`. [3](#0-2) 
The callback is registered with `!msg.is_empty()` as `is_ft_transfer_call`, which evaluates to `false` for the common empty-message case. [4](#0-3) 

**Step 3 — `is_refund_required(false)` unconditionally returns `false`.**
The `else` branch for the non-`ft_transfer_call` case never reads `env::promise_result(0)`. [5](#0-4) 

**Step 4 — Callback takes the success path regardless of actual outcome.**
Because `is_refund_required` returned `false`, `fin_transfer_send_tokens_callback` emits `FinTransferEvent` and sends fees. `remove_fin_transfer` and `revert_lock_actions` are never called. [6](#0-5) 

The refund/recovery path — which calls `remove_fin_transfer` and `revert_lock_actions` — is only reachable when `is_ft_transfer_call = true` and the `ft_transfer_call` promise returns `U128(0)`. [7](#0-6) 

Any subsequent retry of `fin_transfer` with the same proof panics at `add_fin_transfer` with `BridgeError::TransferAlreadyFinalised`, making the freeze permanent. [8](#0-7) 

## Impact Explanation

This matches the Critical impact class: **permanent freezing of bridged funds**. The source-chain tokens (EVM/Solana/Starknet) are already locked or burned at the time `fin_transfer` is called. The destination nonce is permanently consumed. The recipient never receives tokens. No admin function exists to remove a nonce from `finalised_transfers` outside the callback's refund path, and that path is structurally unreachable for plain `ft_transfer` outcomes.

## Likelihood Explanation

The affected code path is the default path for any native NEP-141 token bridged with an empty `msg`. Many widely-deployed NEP-141 tokens (USDC.e, USDT, and other stablecoin wrappers) implement pause or blacklist mechanisms. No privileged access is required: any relayer can submit a valid cross-chain proof to `fin_transfer`. If the token is paused at the moment of finalization — even transiently — the silent-failure path is triggered. The attacker does not need to control the token; they only need to time the submission when a known-pausable token is paused.

## Recommendation

In `is_refund_required`, when `is_ft_transfer_call = false`, inspect `env::promise_result(0)` and return `true` if the promise failed:

```rust
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    if is_ft_transfer_call {
        // existing logic unchanged
        match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
            Ok(value) => {
                if let Ok(amount) = near_sdk::serde_json::from_slice::<U128>(&value) {
                    amount.0 == 0
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    } else {
        // NEW: treat a failed ft_transfer as requiring refund/revert
        matches!(env::promise_result(0), PromiseResult::Failed)
    }
}
```

This ensures that when `ft_transfer` panics (paused token, insufficient balance, etc.), `fin_transfer_send_tokens_callback` calls `remove_fin_transfer` and `revert_lock_actions`, emits `FailedFinTransferEvent`, and allows the transfer to be retried once the token is unpaused. [9](#0-8) 

## Proof of Concept

1. Register a pausable NEP-141 token (e.g., a USDC wrapper) with the NEAR omni-bridge as a native (non-deployed) token.
2. A user initiates a transfer from EVM → NEAR for that token; EVM-side tokens are locked in the EVM connector.
3. The token issuer pauses the token (or it is already paused).
4. A relayer submits a valid proof to `fin_transfer` on NEAR.
5. `fin_transfer_callback` → `process_fin_transfer_to_near` → `add_fin_transfer` inserts the nonce into `finalised_transfers`.
6. `send_tokens` dispatches `ft_transfer` with `is_ft_transfer_call = false`; the token contract panics with "paused".
7. NEAR runtime calls `fin_transfer_send_tokens_callback(is_ft_transfer_call = false)`.
8. `is_refund_required(false)` returns `false`; callback emits `FinTransferEvent` and exits.
9. `finalised_transfers` still contains the nonce — any retry of `fin_transfer` panics with `ERR_TRANSFER_ALREADY_FINALISED`.
10. User's funds are permanently frozen; no recovery path exists on either chain.

A local integration test can reproduce this by deploying a mock NEP-141 token that panics on `ft_transfer`, registering it with the bridge, submitting a finalization proof, and asserting that (a) `FinTransferEvent` is logged, (b) the recipient balance is zero, and (c) a second `fin_transfer` call with the same proof panics with `TransferAlreadyFinalised`.

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

**File:** near/omni-bridge/src/lib.rs (L1719-1747)
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
    }
```

**File:** near/omni-bridge/src/lib.rs (L1784-1804)
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
    }
```

**File:** near/omni-bridge/src/lib.rs (L1875-1875)
```rust
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());
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

**File:** near/omni-bridge/src/lib.rs (L2226-2234)
```rust
    fn add_fin_transfer(&mut self, transfer_id: &TransferId) -> NearToken {
        let storage_usage = env::storage_usage();
        require!(
            self.finalised_transfers.insert(transfer_id),
            BridgeError::TransferAlreadyFinalised.as_ref()
        );
        env::storage_byte_cost()
            .saturating_mul((env::storage_usage().saturating_sub(storage_usage)).into())
    }
```
