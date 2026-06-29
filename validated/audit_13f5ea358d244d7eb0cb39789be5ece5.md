Audit Report

## Title
`fin_transfer_send_tokens_callback` Ignores `ft_transfer` Failure, Permanently Freezing Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

## Summary

When finalizing an inbound transfer to a NEAR recipient, `process_fin_transfer_to_near` records the transfer as finalized via `add_fin_transfer` before the token delivery succeeds. When `msg` is empty, `send_tokens` issues a plain `ft_transfer`; if that call fails, the callback `fin_transfer_send_tokens_callback` unconditionally treats the outcome as success because `is_refund_required(false)` always returns `false`. The transfer ID remains in `finalised_transfers` with no recovery path, permanently freezing the escrowed tokens inside the bridge.

## Finding Description

`process_fin_transfer_to_near` calls `add_fin_transfer` at line 1875, inserting the transfer ID into `finalised_transfers` before any token movement occurs. [1](#0-0) 

It then calls `send_tokens`, which — when the token is non-deployed and `msg` is empty — issues a plain `ft_transfer` cross-contract call: [2](#0-1) 

The `.then()` chains `fin_transfer_send_tokens_callback` with `is_ft_transfer_call = !msg.is_empty()`, so when `msg` is empty the flag is `false`: [3](#0-2) 

Inside the callback, `is_refund_required(false)` takes the `else` branch and unconditionally returns `false`, never inspecting the promise result: [4](#0-3) 

Because `is_refund_required` returns `false`, the callback always enters the success branch, emits `FinTransferEvent`, and sends fees — even when the underlying `ft_transfer` panicked: [5](#0-4) 

The revert path (`burn_tokens_if_needed`, `revert_lock_actions`, `remove_fin_transfer`) is never reached for the `ft_transfer` case: [6](#0-5) 

## Impact Explanation

Escrowed non-deployed NEP-141 tokens held by the bridge are permanently stranded. The transfer ID is in `finalised_transfers` so re-submission is blocked. This is a direct, irreversible loss of bridged funds matching the critical impact category: *permanent freezing of bridged funds*.

## Likelihood Explanation

Any non-deployed NEP-141 token with a blacklist, pause, or custom transfer restriction can trigger this. USDC on NEAR (a prominent non-deployed token) has a well-known blacklist. A relayer — an unprivileged external actor — calls the public `fin_transfer` entry point. No privileged access, no victim mistake, and no external oracle is required. The condition (recipient blacklisted between initiation and finalization) is realistic and can also be self-inflicted by a malicious actor to grief the protocol's accounting.

## Recommendation

In `fin_transfer_send_tokens_callback`, check the promise result even when `is_ft_transfer_call = false`. If `env::promise_result_checked(0, ...)` returns `Err`, treat it as a failure: call `revert_lock_actions`, `remove_fin_transfer`, and emit `FailedFinTransferEvent`. Alternatively, restructure `process_fin_transfer_to_near` so that `add_fin_transfer` is called only inside the callback after confirming the token transfer succeeded, mirroring the pattern used for the `ft_transfer_call` refund path.

## Proof of Concept

1. Token `T` is a non-deployed NEP-141 token with a blacklist; the bridge holds 1000 `T` in escrow for a pending inbound transfer to `alice.near`.
2. `alice.near` is added to `T`'s blacklist by the token issuer.
3. A relayer calls `fin_transfer` with a valid proof. `process_fin_transfer_to_near` executes:
   - `add_fin_transfer(transfer_id)` → transfer ID inserted into `finalised_transfers` (L1875).
   - `send_tokens(T, alice.near, 1000, "")` → issues `ft_transfer(alice.near, 1000)` (L2102–2106).
   - `ft_transfer` panics because `alice.near` is blacklisted → promise result is `Failed`.
4. `fin_transfer_send_tokens_callback` is invoked with `is_ft_transfer_call = false`.
5. `is_refund_required(false)` returns `false` (L1800–1803) without reading the promise result.
6. Callback enters the success branch (L1719), emits `FinTransferEvent`, sends fees.
7. 1000 `T` remain in the bridge. The transfer ID is permanently in `finalised_transfers`; re-submission panics. Funds are frozen with no recovery path.

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
