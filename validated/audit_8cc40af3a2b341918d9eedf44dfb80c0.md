Audit Report

## Title
Partial `ft_on_transfer` Refund Permanently Freezes Bridged Tokens in Bridge Contract - (File: `near/omni-bridge/src/lib.rs`)

## Summary

The `is_refund_required` function uses binary logic: it only triggers a full transfer revert when `ft_on_transfer` returns `0` (full rejection). When a recipient contract returns any non-zero partial amount, the function returns `false`, the transfer is finalized, and the partially refunded tokens accumulate in the bridge contract's balance with no recovery path. The integration test suite explicitly confirms this behavior with `expected_locker_balance: 1`.

## Finding Description

`is_refund_required` reads the promise result from `ft_transfer_call` and returns `true` only when `amount.0 == 0`: [1](#0-0) 

Under NEP-141, `ft_transfer_call` invokes the recipient's `ft_on_transfer`, which returns the number of tokens to refund back to the sender (the bridge). The token contract's `ft_resolve_transfer` then credits that refunded amount back to the bridge's token balance. If the recipient returns `499` (partial fill), the bridge receives 499 tokens back into its balance — but `is_refund_required` sees `amount.0 = 500 != 0` and returns `false`.

All three callback paths share this flaw:

- `fin_transfer_send_tokens_callback` at line 1702 proceeds to emit `FinTransferEvent` (line 1745) with no handling of the partial residual. [2](#0-1) 

- `resolve_fast_transfer` at line 906 returns `U128(0)` on the non-refund branch, discarding the partial residual. [3](#0-2) 

- `resolve_utxo_fin_transfer` at line 1025 emits `UtxoTransferEvent` and returns `U128(0)`, again discarding the residual. [4](#0-3) 

The integration test explicitly confirms the stuck-token outcome: with `amount=1000`, `fee=1`, and `return_value=U128(1)` (recipient returns 1 token), `expected_locker_balance: 1` — the bridge retains 1 token permanently. [5](#0-4) 

There is no admin withdrawal function, no recovery path, and no retry mechanism once `FinTransferEvent` is emitted.

## Impact Explanation

This directly causes **permanent freezing of bridged funds**, which is an explicitly listed Critical impact. For non-deployed tokens (e.g., USDC, WETH locked in the bridge): partially refunded tokens accumulate in the bridge contract's balance with no withdrawal or recovery function. The foreign-chain sender has already irrevocably burned or locked their tokens, so there is no retry. For deployed (bridge-minted) tokens: the returned tokens are burned by `ft_resolve_transfer`, destroying supply legitimately owed to the user. In both cases the user suffers a direct, unrecoverable loss of bridged funds.

## Likelihood Explanation

The attack surface is any `fin_transfer`, `fast_fin_transfer`, or UTXO fin transfer call with a non-empty `msg` field. This is a supported, documented feature for DeFi integrations. Any recipient contract implementing slippage protection, minimum output enforcement, or partial-fill logic will return a non-zero amount from `ft_on_transfer` — this is standard NEP-141 behavior, not an edge case. The `msg` field is user-controlled and relayer-submitted, making this reachable by any bridge user without special privileges.

## Recommendation

Replace the binary `is_refund_required` with a function that returns the actual used amount. In each callback (`fin_transfer_send_tokens_callback`, `resolve_fast_transfer`, `resolve_utxo_fin_transfer`), after determining that a full refund is not required, compute `residual = sent_amount - used_amount`. If `residual > 0`, forward the residual tokens to the original recipient or the transfer sender via `ft_transfer` before emitting the finalization event. This ensures no tokens are silently retained in the bridge contract on partial fills.

## Proof of Concept

The integration test at `near/omni-tests/src/fin_transfer.rs` lines 533–545 is a direct, reproducible proof:

1. Transfer of 1000 tokens with fee=1; bridge calls `ft_transfer_call(recipient, 999, msg)`.
2. Recipient's `ft_on_transfer` returns `U128(1)` (partial refund of 1 token).
3. Token contract's `ft_resolve_transfer` credits 1 token back to the bridge's balance.
4. `fin_transfer_send_tokens_callback` is called; `is_refund_required` sees `amount.0 = 998 != 0`, returns `false`.
5. Bridge emits `FinTransferEvent` — transfer finalized.
6. Result: `expected_recipient_balance: 998`, `expected_relayer_balance: 1`, `expected_locker_balance: 1` — 1 token permanently frozen in the bridge. [5](#0-4)

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

**File:** near/omni-bridge/src/lib.rs (L1025-1043)
```rust
        if Self::is_refund_required(is_ft_transfer_call) {
            self.remove_fin_utxo_transfer(
                &utxo_fin_transfer_msg.get_transfer_id(origin_chain),
                storage_owner,
            );
            amount
        } else {
            env::log_str(
                &OmniBridgeEvent::UtxoTransferEvent {
                    token_id,
                    amount,
                    utxo_transfer_message: utxo_fin_transfer_msg,
                    new_transfer_id: None,
                }
                .to_log_string(),
            );

            U128(0)
        }
```

**File:** near/omni-bridge/src/lib.rs (L1702-1745)
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

**File:** near/omni-tests/src/fin_transfer.rs (L533-545)
```rust
    #[case(FinTransferWithMsgCase {
        storage_deposit_accounts: vec![(relayer_account_id(), true)],
        amount: 1000,
        fee: 1,
        msg: TokenReceiverMessage {
            return_value: U128(1),
            panic: false,
            extra_msg: String::new(),
        },
        expected_recipient_balance: 998,
        expected_relayer_balance: 1,
        expected_locker_balance: 1,
    })]
```
