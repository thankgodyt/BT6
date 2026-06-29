Audit Report

## Title
`fin_transfer_send_tokens_callback` Ignores Promise Result for Plain `ft_transfer`/`mint`, Permanently Freezing Bridged Funds — (File: `near/omni-bridge/src/lib.rs`)

## Summary

In `process_fin_transfer_to_near`, the transfer ID is inserted into `finalised_transfers` and `locked_tokens` is decremented before token delivery is confirmed. When `send_tokens` is called with an empty `msg` (the common case), `is_ft_transfer_call = false` is passed to the callback. `is_refund_required(false)` unconditionally returns `false` without reading the promise result, so any failure of the underlying `ft_transfer` or `mint` call is silently treated as success. The transfer is permanently finalized with no retry path, and the recipient never receives their tokens.

## Finding Description

**Step 1 — Finalization flag and accounting mutation occur before delivery.**

`process_fin_transfer_to_near` calls `add_fin_transfer` on its first line:

```rust
// near/omni-bridge/src/lib.rs:1875
let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());
``` [1](#0-0) 

`add_fin_transfer` inserts the `TransferId` into `finalised_transfers`. Any subsequent call to `fin_transfer` for the same proof will panic with `BridgeError::TransferAlreadyFinalised`. [2](#0-1) 

Immediately after, `unlock_tokens_if_needed` decrements `locked_tokens`: [3](#0-2) 

**Step 2 — `is_ft_transfer_call = false` for all plain transfers.**

`send_tokens` is dispatched and the callback is chained with `!msg.is_empty()` as `is_ft_transfer_call`: [4](#0-3) 

For the common case of a plain transfer (empty `msg`), `is_ft_transfer_call = false`. `send_tokens` then dispatches either `mint` (deployed bridge token, lines 2094–2101) or `ft_transfer` (non-deployed token, lines 2102–2106): [5](#0-4) 

**Step 3 — `is_refund_required(false)` never reads the promise result.**

```rust
// near/omni-bridge/src/lib.rs:1800-1803
} else {
    // Not ft_transfer_call: don't refund
    false
}
``` [6](#0-5) 

When `is_ft_transfer_call = false`, the function returns `false` without calling `env::promise_result_checked`. A failed `ft_transfer` or `mint` promise is indistinguishable from a successful one.

**Step 4 — Callback unconditionally takes the "success" path.** [7](#0-6) 

Because `is_refund_required` returns `false`, the callback skips `burn_tokens_if_needed`, `revert_lock_actions`, and `remove_fin_transfer`, and instead mints/transfers the relayer fee and emits `FinTransferEvent` — even when the underlying token delivery failed.

**Step 5 — No recovery path.**

`finalised_transfers` now contains the transfer ID. Any retry of `fin_transfer` with the same proof panics with `TransferAlreadyFinalised`. The `locked_tokens` counter was already decremented. For non-deployed tokens, the underlying tokens are stuck in the bridge contract. For deployed bridge tokens, they were burned on the source chain and the NEAR-side mint failed silently.

## Impact Explanation

This is a **Critical** impact matching "permanent freezing of bridged funds." For non-deployed tokens (e.g., USDC locked on Ethereum), the tokens remain locked in the bridge contract but `locked_tokens` is decremented, breaking the accounting invariant — the recipient never receives them and no retry is possible. For deployed bridge tokens (burned on source chain, to be minted on NEAR), the tokens are burned on the source chain and the NEAR mint fails silently, causing permanent, unrecoverable loss. The relayer still collects its fee in the "success" branch, creating a perverse incentive.

## Likelihood Explanation

The trigger requires `send_tokens` to fail for a transfer with an empty `msg`. Realistic failure modes reachable by an unprivileged external actor include: (1) a non-standard token contract whose `ft_transfer` panics under edge conditions (fee-on-transfer tokens, transfer-hook logic); (2) gas exhaustion if the gas forwarded to `ft_transfer` or `mint` is insufficient; (3) the wNEAR path — `send_tokens` for wNEAR with empty `msg` dispatches `near_withdraw → near_withdraw_callback`; if `near_withdraw` fails, the outer promise result is `Failed`, but `is_refund_required(false)` still returns `false`; (4) a deployed bridge token whose `mint` reverts for any reason. Likelihood is **medium**: the happy path works correctly, but the structural absence of any promise-result check for the non-`ft_transfer_call` branch means any of the above edge cases silently finalizes the transfer and loses funds.

## Recommendation

In `fin_transfer_send_tokens_callback`, check the promise result regardless of `is_ft_transfer_call`. When `is_ft_transfer_call = false`, call `env::promise_result_checked(0, ...)` and treat a `Failed` promise as a revert condition: call `revert_lock_actions`, `remove_fin_transfer`, and emit `FailedFinTransferEvent`, mirroring the existing revert logic in the `is_refund_required = true` branch. The `is_refund_required` helper should be extended or replaced with a broader check that covers both `ft_transfer_call` refund semantics and plain `ft_transfer`/`mint` failure detection.

## Proof of Concept

1. A user initiates a transfer of a non-deployed token (e.g., USDC) from Ethereum to a NEAR account with no `msg` field.
2. The EVM-side `initTransfer` locks the tokens and emits an event.
3. A relayer calls `fin_transfer` on the NEAR bridge with a valid proof.
4. `process_fin_transfer_to_near` runs: `add_fin_transfer` marks the transfer finalized (line 1875); `unlock_tokens_if_needed` decrements `locked_tokens` (lines 1881–1885); `send_tokens` dispatches `ft_transfer` to the NEAR token contract.
5. The `ft_transfer` call panics (e.g., the token contract has a non-standard guard, or gas is exhausted).
6. `fin_transfer_send_tokens_callback` is invoked. `is_ft_transfer_call = false`, so `is_refund_required` returns `false` at line 1802 without reading the promise result.
7. The callback enters the "success" branch (line 1719): mints/transfers the fee to the relayer, emits `FinTransferEvent`.
8. The transfer ID remains in `finalised_transfers`. Any retry of `fin_transfer` with the same proof panics with `ERR_TRANSFER_ALREADY_FINALISED`.
9. The user's USDC is permanently stuck in the bridge contract; the relayer collected its fee.

A unit test can reproduce this by mocking `ft_transfer` to return a failed promise and asserting that `fin_transfer_send_tokens_callback` incorrectly emits `FinTransferEvent` instead of `FailedFinTransferEvent`, and that `finalised_transfers` still contains the transfer ID after the callback.

### Citations

**File:** near/omni-bridge/src/lib.rs (L1702-1746)
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

**File:** near/omni-bridge/src/lib.rs (L2094-2106)
```rust
            ext_token::ext(token)
                .with_attached_deposit(deposit)
                .with_static_gas(MINT_TOKEN_GAS.saturating_add(ft_transfer_call_gas))
                .mint(
                    recipient,
                    amount,
                    (!msg.is_empty()).then(|| msg.to_string()),
                )
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
