Audit Report

## Title
Unhandled `ft_transfer` Failure in `fin_transfer_send_tokens_callback` Permanently Locks Bridged Tokens — (File: `near/omni-bridge/src/lib.rs`)

## Summary

When `process_fin_transfer_to_near` finalizes a cross-chain transfer to a NEAR recipient with an empty `msg`, it calls `send_tokens` which issues a plain `ft_transfer`. The callback `fin_transfer_send_tokens_callback` delegates failure detection entirely to `is_refund_required`, which unconditionally returns `false` when `is_ft_transfer_call = false` — never reading the promise result. If `ft_transfer` fails, `locked_tokens` is permanently decremented, the transfer ID remains in `finalised_transfers` blocking replay, and the token balance is stranded in the bridge contract with no recovery path.

## Finding Description

`process_fin_transfer_to_near` records the transfer as finalised and decrements `locked_tokens` before dispatching `send_tokens`: [1](#0-0) 

`send_tokens` issues a plain `ft_transfer` (no cross-contract callback to the receiver) when `msg` is empty and the token is not a deployed token: [2](#0-1) 

`!msg.is_empty()` is passed as `is_ft_transfer_call` to the callback: [3](#0-2) 

Inside `is_refund_required`, the `else` branch for `is_ft_transfer_call = false` returns `false` unconditionally without ever calling `env::promise_result_checked`: [4](#0-3) 

Consequently, `fin_transfer_send_tokens_callback` always takes the success branch regardless of whether `ft_transfer` succeeded or failed: [5](#0-4) 

`revert_lock_actions` and `remove_fin_transfer` are never reached on a plain `ft_transfer` failure. The existing test `test_fin_transfer_callback_refund_restores_locked_tokens` only exercises the `is_ft_transfer_call = true` path and does not cover this case. [6](#0-5) 

## Impact Explanation

This is a concrete instance of **permanent freezing of bridged funds**. For every affected transfer: the `locked_tokens[(origin_chain, token)]` counter is permanently decremented by the full transfer amount even though no tokens were delivered; the transfer ID is permanently recorded in `finalised_transfers` making re-finalization impossible; and the actual NEP-141 token balance remains held by the bridge contract with no accounting entry pointing to it and no privileged function able to release it without DAO intervention. This matches the Critical impact class: permanent freezing of bridged funds across NEAR and EVM flows.

## Likelihood Explanation

An unprivileged external user can trigger this deterministically. The attacker controls NEAR recipient account `R`, registers storage for token `T` on the token contract (storage check passes), waits for a relayer to call `fin_transfer` (a public call), then submits a `storage_unregister` transaction for `R` on the token contract in the same block. Because `R` holds zero balance of `T` at that point, `storage_unregister` succeeds. When the `ft_transfer` receipt is subsequently processed, it panics because `R` has no storage registration. The callback takes the success path. The attacker sacrifices their origin-chain tokens once to permanently corrupt the bridge's `locked_tokens` invariant. A non-adversarial path also exists: any transient panic in the token contract (paused state, buggy NEP-141 implementation) during `ft_transfer` produces the same permanent lock.

## Recommendation

`is_refund_required` must inspect the promise result for the plain `ft_transfer` case as well. The `else` branch should call `env::promise_result_checked(0, usize::MAX)` and return `true` on `Err`. Alternatively, add a `#[callback_result] ft_transfer_result: Result<(), near_sdk::PromiseError>` parameter to `fin_transfer_send_tokens_callback` and revert lock actions whenever the result is `Err`, regardless of `is_ft_transfer_call`. The fix must cover all three non-`ft_transfer_call` paths in `send_tokens`: plain `ft_transfer`, `mint` with empty msg, and `near_withdraw`. [7](#0-6) 

## Proof of Concept

1. Deploy the bridge on a local NEAR sandbox with a standard NEP-141 token `T` locked from Ethereum (bridge holds `N` units, `locked_tokens[(Eth, T)] = N`).
2. Create attacker NEAR account `R`; call `storage_deposit` on `T` for `R` (minimum deposit).
3. Submit a `fin_transfer` call from a relayer with a valid Ethereum proof for a transfer of `N` tokens to `R`, empty `msg`. The `fin_transfer_callback` runs: storage check passes, `locked_tokens[(Eth, T)]` becomes `0`, `finalised_transfers` records the transfer ID, `send_tokens` schedules `ft_transfer(R, N)`.
4. Before the `ft_transfer` receipt executes, submit `storage_unregister(force=false)` on `T` for `R` (succeeds because `R` balance is still `0`).
5. The `ft_transfer` receipt executes and panics (no storage for `R`).
6. `fin_transfer_send_tokens_callback` runs with `is_ft_transfer_call = false`; `is_refund_required` returns `false`; success branch executes.
7. Assert: `locked_tokens[(Eth, T)] == 0` (not restored), transfer ID still in `finalised_transfers`, bridge token balance unchanged at `N` — tokens permanently frozen.

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

**File:** near/omni-bridge/src/lib.rs (L1973-1973)
```rust
                    !msg.is_empty(),
```

**File:** near/omni-bridge/src/lib.rs (L2102-2106)
```rust
        } else if msg.is_empty() {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
```

**File:** near/omni-bridge/src/tests/lib_test.rs (L1061-1067)
```rust
    contract.fin_transfer_send_tokens_callback(
        transfer_message,
        &fee_recipient,
        true,
        &recipient,
        lock_actions,
    );
```
