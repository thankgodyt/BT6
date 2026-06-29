Audit Report

## Title
Silent Failure of `ft_transfer`/`mint` in `fin_transfer_send_tokens_callback` Causes Permanent Loss of Bridged Funds — (File: `near/omni-bridge/src/lib.rs`)

## Summary

`is_refund_required` unconditionally returns `false` when `is_ft_transfer_call` is `false`, without inspecting the promise result. Since `is_ft_transfer_call` is set to `!msg.is_empty()`, any plain `ft_transfer` or `mint` call (empty `msg`) that fails will cause `fin_transfer_send_tokens_callback` to execute the success branch: the fee is paid out, `FinTransferEvent` is emitted, and `remove_fin_transfer` is never called. The transfer nonce was already consumed by `add_fin_transfer` before `send_tokens` was invoked, so the recipient receives nothing and the transfer cannot be replayed — funds are permanently lost.

## Finding Description

**Root cause — `is_refund_required` ignores promise result for non-`ft_transfer_call` paths:** [1](#0-0) 

When `is_ft_transfer_call` is `false`, the function returns `false` at line 1802 with the comment "Not ft_transfer_call: don't refund" — it never calls `env::promise_result_checked`.

**`is_ft_transfer_call` is `false` for plain `ft_transfer`/`mint`:** [2](#0-1) 

`!msg.is_empty()` is `false` when `msg` is empty, which is the case for all plain token deliveries (not `ft_transfer_call`).

**`send_tokens` issues `mint` or `ft_transfer` when `msg` is empty:** [3](#0-2) 

**Nonce consumed before `send_tokens` is called:** [4](#0-3) 

**Callback takes the success branch on failure — fee paid, event emitted, `remove_fin_transfer` never called:** [5](#0-4) 

The same flaw exists in `resolve_fast_transfer`: [6](#0-5) 

And in `resolve_utxo_fin_transfer`: [7](#0-6) 

## Impact Explanation

This is a **permanent loss of bridged funds**. The transfer ID is finalized in storage before the token delivery attempt. If delivery fails and the callback silently treats it as success, the transfer ID cannot be replayed (the prover nonce is consumed), `remove_fin_transfer` is never called, and the recipient's balance is zero. Funds locked/burned on the source chain have no recourse on NEAR. This matches the allowed critical impact: *permanent freezing / loss of bridged funds across NEAR, EVM, Solana, Bitcoin, or Wormhole-routed flows*.

## Likelihood Explanation

Any failure of `ft_transfer` or `mint` on the destination token contract triggers this. Realistic causes include: a stablecoin (USDC, USDT) paused by its issuer (a documented real-world event), a bridge token whose `mint` panics on an edge case, or insufficient gas allocated to the token call. No privileged access is required — the failure is triggered by normal bridge operation when the downstream token contract rejects the call. The root cause is entirely within the bridge's own callback logic.

## Recommendation

`is_refund_required` must check the promise result even when `is_ft_transfer_call` is `false`:

```rust
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    if is_ft_transfer_call {
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
        // ft_transfer or mint: refund if the promise failed
        env::promise_result_checked(0, 0).is_err()
    }
}
```

Apply the same fix to `resolve_fast_transfer` and `resolve_utxo_fin_transfer`.

## Proof of Concept

1. User bridges USDC from Ethereum to NEAR via `initTransfer` — USDC is locked on Ethereum.
2. Relayer calls `fin_transfer` on the NEAR bridge with a valid proof.
3. `fin_transfer_callback` decodes the proof and calls `process_fin_transfer_to_near`.
4. `add_fin_transfer` is called at L1875 — transfer nonce is consumed.
5. `send_tokens` issues `ft_transfer(recipient, amount)` with empty `msg` (deployed token path: `mint`).
6. USDC on NEAR is paused; `ft_transfer`/`mint` fails.
7. `fin_transfer_send_tokens_callback` is invoked with `is_ft_transfer_call = false`.
8. `is_refund_required(false)` returns `false` at L1802 without reading the promise result.
9. The else branch at L1719 executes: fee is minted/transferred to relayer, `FinTransferEvent` is emitted.
10. `remove_fin_transfer` is never called; transfer ID stays finalized.
11. Recipient balance: 0. Transfer nonce: consumed. Source-chain funds: permanently locked. No replay possible.

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

**File:** near/omni-bridge/src/lib.rs (L1025-1031)
```rust
        if Self::is_refund_required(is_ft_transfer_call) {
            self.remove_fin_utxo_transfer(
                &utxo_fin_transfer_msg.get_transfer_id(origin_chain),
                storage_owner,
            );
            amount
        } else {
```

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

**File:** near/omni-bridge/src/lib.rs (L2082-2106)
```rust
        } else if is_deployed_token {
            let deposit = if msg.is_empty() {
                NO_DEPOSIT
            } else {
                ONE_YOCTO
            };

            require!(
                ft_transfer_call_gas >= MIN_FT_TRANSFER_CALL_GAS,
                BridgeError::NotEnoughGasForTokenTransfer(ft_transfer_call_gas).as_ref()
            );

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
