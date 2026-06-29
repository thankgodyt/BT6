Audit Report

## Title
`ft_transfer` Failure Silently Ignored in `fin_transfer_send_tokens_callback`, Causing Permanent Loss of Bridged Funds — (File: `near/omni-bridge/src/lib.rs`)

## Summary

When finalizing an inbound NEAR-destined transfer using a plain `ft_transfer` (empty `msg`), `fin_transfer_send_tokens_callback` never inspects the promise result. `is_refund_required` unconditionally returns `false` for the non-`ft_transfer_call` path, so a failed `ft_transfer` (e.g., recipient is blocklisted by the token issuer) is silently treated as success. Because `add_fin_transfer` writes the transfer ID to `finalised_transfers` before `send_tokens` is dispatched, and the prover has already consumed the proof, there is no retry or recovery path — the recipient's funds are permanently destroyed.

## Finding Description

**Step 1 — Transfer finalized before delivery:**
`process_fin_transfer_to_near` calls `add_fin_transfer` at line 1875, permanently recording the transfer ID in `finalised_transfers`, then calls `send_tokens`. [1](#0-0) 

**Step 2 — Callback registered with `is_ft_transfer_call = !msg.is_empty()`:**
When `msg` is empty, `is_ft_transfer_call = false` is passed to the callback. [2](#0-1) 

**Step 3 — Plain `ft_transfer` dispatched for non-deployed tokens with empty `msg`:** [3](#0-2) 

**Step 4 — `is_refund_required` returns `false` unconditionally for the plain `ft_transfer` path:**
The `else` branch at line 1800 never calls `env::promise_result_checked`, so a `Failed` promise result is invisible to the callback. [4](#0-3) 

**Step 5 — Callback unconditionally takes the success branch:**
Because `is_refund_required` returned `false`, the callback pays the relayer fee and emits `FinTransferEvent`, regardless of whether the underlying `ft_transfer` succeeded. [5](#0-4) 

The refund/revert branch — which calls `revert_lock_actions`, `remove_fin_transfer`, and emits `FailedFinTransferEvent` — is never reached for the plain `ft_transfer` case. [6](#0-5) 

## Impact Explanation

A recipient whose address is blocklisted by the token contract (e.g., USDC's Circle-controlled on-chain blocklist) will have their `ft_transfer` promise fail. The bridge contract does not detect this failure, marks the transfer as successfully finalized, pays the relayer fee, and emits a success event. The proof is consumed by the prover and `finalised_transfers` permanently records the transfer ID. Any re-submission of the same proof is rejected. The recipient receives zero tokens with no recourse. This is a concrete, permanent loss of bridged funds matching the Critical allowed impact.

## Likelihood Explanation

No attacker capability is required beyond the token issuer's normal administrative control over their own token contract. USDC (a production token registered with the bridge) has a Circle-controlled blocklist. A user added to the blocklist after initiating a cross-chain transfer — or targeted by a compliance action during finalization — will trigger this path through normal relayer operation. The relayer submitting `fin_transfer` need not be malicious; the loss occurs automatically.

## Recommendation

`is_refund_required` must inspect `env::promise_result_checked(0, ...)` regardless of whether `is_ft_transfer_call` is true or false. For the plain `ft_transfer` case, a `Failed` promise result (i.e., `Err(_)` from `promise_result_checked`) should be treated as a refund trigger: call `revert_lock_actions`, `remove_fin_transfer`, and emit `FailedFinTransferEvent` instead of paying the fee and emitting `FinTransferEvent`. The existing `ft_transfer_call` refund logic already demonstrates the correct pattern and should be extended to cover the `ft_transfer` case.

## Proof of Concept

1. Register USDC (a non-deployed NEP-141 token with a Circle blocklist) with the bridge.
2. Alice initiates a transfer of 10,000 USDC from Ethereum to her NEAR address with an empty `msg`.
3. Circle adds Alice's NEAR address to the USDC blocklist.
4. A relayer calls `fin_transfer` with a valid Ethereum proof.
5. `fin_transfer_callback` → `process_fin_transfer_to_near`:
   - `add_fin_transfer` writes Alice's transfer ID to `finalised_transfers` (line 1875).
   - `send_tokens` dispatches `ft_transfer(alice, 10000, None)` (lines 2102–2106).
6. USDC's `ft_transfer` panics (Alice is blocklisted). Promise result = `Failed`.
7. `fin_transfer_send_tokens_callback` is invoked with `is_ft_transfer_call = false`.
8. `is_refund_required(false)` returns `false` without reading the promise result (lines 1800–1803).
9. The callback pays the relayer fee and emits `FinTransferEvent`. Alice receives 0 USDC.
10. Any retry of `fin_transfer` with the same proof is rejected by the prover (proof consumed) and by `finalised_transfers` (transfer ID already recorded). Alice's 10,000 USDC is permanently lost.

A local integration test can reproduce this by deploying a mock NEP-141 token that panics on `ft_transfer` to a specific account, then executing the full `fin_transfer` → callback flow and asserting that `finalised_transfers` contains the transfer ID while the recipient balance remains zero.

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
