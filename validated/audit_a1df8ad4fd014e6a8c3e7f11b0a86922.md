The code confirms all claims. Let me verify one more detail about admin recovery paths.

All code claims are confirmed. The `remove_fin_transfer` call only exists inside the `is_refund_required` branch (line 1714), which is never reached for plain `ft_transfer` failures. No admin recovery path exists.

---

Audit Report

## Title
`ft_transfer` Failure in `fin_transfer_send_tokens_callback` Permanently Freezes Bridged Funds Without Recovery - (File: near/omni-bridge/src/lib.rs)

## Summary

When finalizing a cross-chain transfer to a NEAR recipient using a non-deployed (locked) token with an empty `msg`, the bridge commits the transfer ID to `finalised_transfers` before the `ft_transfer` push-payment is attempted. If `ft_transfer` fails (e.g., recipient is blacklisted in a USDC-like token contract), `fin_transfer_send_tokens_callback` unconditionally takes the success branch because `is_refund_required` returns `false` without inspecting the promise result for non-`ft_transfer_call` paths. The transfer ID is permanently finalized, the recipient receives zero tokens, locked-token accounting is decremented, and no recovery path exists.

## Finding Description

**Step 1 — Finalization committed before push-payment.**

`process_fin_transfer_to_near` calls `add_fin_transfer` as its very first action: [1](#0-0) 

`add_fin_transfer` inserts the transfer ID into `finalised_transfers` and panics if already present: [2](#0-1) 

This state is committed when the parent receipt completes. The subsequent `send_tokens` and `fin_transfer_send_tokens_callback` execute as separate receipts; their failure does not roll back `finalised_transfers`.

**Step 2 — Locked-token accounting decremented before push-payment.**

`unlock_tokens_if_needed` is called before `send_tokens`, decrementing the locked-token counter regardless of whether delivery succeeds: [3](#0-2) 

**Step 3 — `send_tokens` uses `ft_transfer` for non-deployed tokens with empty `msg`.** [4](#0-3) 

`ft_transfer` panics as a NEAR receipt if the recipient is blacklisted, the token is paused, or any token-level restriction applies.

**Step 4 — Callback never checks the `ft_transfer` promise result.**

`is_refund_required` only inspects the promise result when `is_ft_transfer_call` is `true`. When `msg.is_empty()`, `is_ft_transfer_call = false` and the function unconditionally returns `false`: [5](#0-4) 

So `fin_transfer_send_tokens_callback` always takes the else-branch, emits `FinTransferEvent`, and sends fees — regardless of whether `ft_transfer` succeeded: [6](#0-5) 

**Step 5 — No recovery path.**

`remove_fin_transfer` is only called inside the `is_refund_required == true` branch (line 1714), which is never reached for plain `ft_transfer` failures. There is no admin function to remove an entry from `finalised_transfers`. Retrying `fin_transfer` panics with `TransferAlreadyFinalised`.

## Impact Explanation

This is a **permanent freezing of bridged funds**, which is explicitly within the Critical allowed impact scope. Specifically:

- The transfer ID is permanently in `finalised_transfers`; `fin_transfer` cannot be retried.
- The recipient receives zero tokens.
- For non-deployed (locked) tokens, the funds remain physically in the bridge contract with no withdrawal mechanism.
- The locked-token counter is decremented, leaving accounting permanently inconsistent.
- `FinTransferEvent` is emitted, falsely signaling success to off-chain observers and the origin chain.

## Likelihood Explanation

Any NEP-141 token implementing a transfer blacklist (USDC, USDT, and similar regulated stablecoins) can trigger this path. The recipient address is fully attacker-controlled from the origin chain. A user can specify any NEAR account as recipient; if that account is blacklisted in the token contract — whether by the token issuer for regulatory reasons or deliberately — the next relayer call to `fin_transfer` will permanently freeze the funds. No bridge admin action is required; the trigger is a standard token-contract feature exercised by the token issuer.

## Recommendation

`fin_transfer_send_tokens_callback` must check the promise result for the plain `ft_transfer` path. Specifically, `is_refund_required` should be extended to call `env::promise_result_checked` when `is_ft_transfer_call` is `false` and detect a failed receipt. If the promise failed, the callback should:

1. Call `remove_fin_transfer` to un-finalize the transfer ID.
2. Call `revert_lock_actions` to restore the locked-token accounting.
3. Emit `FailedFinTransferEvent` so the relayer and origin chain can observe the failure and retry.

This mirrors the existing `ft_transfer_call` refund logic and closes the gap for the plain `ft_transfer` path.

## Proof of Concept

1. Deploy a NEP-141 token on NEAR with a blacklist (USDC-equivalent).
2. Register the token with the bridge on both EVM and NEAR sides (non-deployed/locked path).
3. User on EVM calls `initTransfer` sending 1000 USDC to NEAR recipient `alice.near` with empty `msg`.
4. Token issuer blacklists `alice.near` in the NEAR token contract.
5. Relayer calls `fin_transfer` with the proof.
6. `fin_transfer_callback` → `process_fin_transfer_to_near`:
   - `add_fin_transfer` inserts transfer ID into `finalised_transfers` (committed).
   - `unlock_tokens_if_needed` decrements locked-token counter.
   - `send_tokens` dispatches `ft_transfer(alice.near, 1000, None)`.
   - `ft_transfer` panics because `alice.near` is blacklisted — receipt fails.
7. `fin_transfer_send_tokens_callback` is called with a failed promise result.
   - `is_ft_transfer_call = false` → `is_refund_required` returns `false` without reading the promise.
   - Callback takes the success branch, emits `FinTransferEvent`, sends fees.
8. `alice.near` has 0 tokens. Transfer ID is permanently finalized. Retrying `fin_transfer` panics with `TransferAlreadyFinalised`. 1000 USDC are permanently frozen in the bridge contract with no recovery path.

### Citations

**File:** near/omni-bridge/src/lib.rs (L1702-1747)
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

**File:** near/omni-bridge/src/lib.rs (L1881-1885)
```rust
        let lock_actions = vec![self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        )];
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
