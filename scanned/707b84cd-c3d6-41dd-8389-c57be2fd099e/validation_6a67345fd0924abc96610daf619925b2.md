### Title
Silent Failure of `ft_transfer`/`mint` in `fin_transfer_send_tokens_callback` Causes Permanent Loss of Bridged Funds — (`near/omni-bridge/src/lib.rs`)

---

### Summary

`fin_transfer_send_tokens_callback` uses `is_refund_required(is_ft_transfer_call)` to decide whether to revert a failed token delivery. When `msg` is empty, `is_ft_transfer_call` is `false`, and `is_refund_required` unconditionally returns `false` **without inspecting the promise result**. If the downstream `ft_transfer` or `mint` call fails for any reason (e.g., the token contract is paused), the callback silently treats the failure as success: the transfer nonce is permanently consumed, the `FinTransferEvent` is emitted, and the recipient never receives their tokens.

---

### Finding Description

**`send_tokens` dispatch** — when `msg` is empty the function issues either `mint` (deployed bridge token) or `ft_transfer` (native/locked token), and the caller passes `is_ft_transfer_call = !msg.is_empty()` — i.e. `false`. [1](#0-0) 

**`is_refund_required` short-circuits to `false`** when `is_ft_transfer_call` is `false`, never reading the promise result: [2](#0-1) 

**`fin_transfer_send_tokens_callback` branches on that return value.** When `is_refund_required` returns `false`, the "success" branch runs: fee is paid out, `FinTransferEvent` is logged, and `remove_fin_transfer` is **never called** — the transfer ID stays permanently finalised: [3](#0-2) 

The transfer nonce is consumed by `add_fin_transfer` **before** `send_tokens` is called: [4](#0-3) 

So if `ft_transfer` or `mint` fails, the nonce is consumed, the transfer is marked finalised, but the recipient receives nothing. The same flaw exists in `resolve_fast_transfer` and `resolve_utxo_fin_transfer`: [5](#0-4) [6](#0-5) 

---

### Impact Explanation

A user bridges tokens (e.g., USDC) from an EVM chain to NEAR. Their tokens are locked/burned on the source chain. On NEAR, `fin_transfer_callback` consumes the proof nonce and calls `process_fin_transfer_to_near`, which records the transfer ID as finalised and calls `send_tokens`. If `ft_transfer` fails (token paused, contract panic, etc.), the callback silently treats it as success. The transfer ID cannot be replayed (nonce consumed by the prover), and `remove_fin_transfer` is never called. The user's funds are permanently lost — locked on the source chain with no recourse on NEAR.

This matches the allowed critical impact: **permanent freezing / loss of bridged funds**.

---

### Likelihood Explanation

The trigger is any failure of `ft_transfer` or `mint` on the destination token contract. Realistic causes include:

- A stablecoin (USDC, USDT) paused by its issuer — a well-documented, real-world event.
- A bridge token whose `mint` function panics due to an edge case.
- Insufficient gas allocated to the token call (gas budget miscalculation).

The root cause is entirely within the bridge's own callback logic, not solely in external dependency behaviour. The original StakedEXA report was accepted on the same basis: the external component (Market) being paused exposed a missing guard in the calling contract.

---

### Recommendation

`is_refund_required` must check the promise result even when `is_ft_transfer_call` is `false`:

```rust
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    if is_ft_transfer_call {
        // existing ft_transfer_call logic
        match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
            Ok(value) => serde_json::from_slice::<U128>(&value)
                .map(|a| a.0 == 0)
                .unwrap_or(false),
            Err(_) => true,  // promise failed → refund required
        }
    } else {
        // ft_transfer or mint: refund if the promise failed
        env::promise_result_checked(0, 0).is_err()
    }
}
```

Additionally, `fin_transfer_send_tokens_callback`, `resolve_fast_transfer`, and `resolve_utxo_fin_transfer` should all treat a failed promise as requiring a refund/revert, regardless of the transfer type.

---

### Proof of Concept

1. User initiates a USDC transfer from Ethereum to NEAR via `initTransfer` on `OmniBridge.sol` — USDC is locked.
2. Relayer calls `fin_transfer` on the NEAR bridge with a valid proof.
3. `fin_transfer_callback` decodes the proof, calls `process_fin_transfer_to_near`, which calls `add_fin_transfer` (nonce consumed) then `send_tokens` → `ft_transfer(recipient, amount)`.
4. USDC on NEAR is paused; `ft_transfer` fails.
5. `fin_transfer_send_tokens_callback` is invoked with `is_ft_transfer_call = false`.
6. `is_refund_required(false)` returns `false` without reading the promise result.
7. The "success" branch executes: fee is paid, `FinTransferEvent` emitted, transfer stays finalised.
8. Recipient balance: 0. Transfer nonce: consumed. User funds: permanently lost. [7](#0-6) [2](#0-1) [8](#0-7)

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
