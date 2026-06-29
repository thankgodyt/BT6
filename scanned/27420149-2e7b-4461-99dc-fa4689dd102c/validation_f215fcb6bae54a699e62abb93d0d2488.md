### Title
`fin_transfer_send_tokens_callback` Ignores `ft_transfer`/`mint` Failure, Permanently Freezing Inbound Bridged Funds — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

When an inbound transfer (foreign chain → NEAR) is finalized via `fin_transfer`, the bridge marks the transfer as finalized in `finalised_transfers` before the actual token delivery (`ft_transfer` or `mint`) executes. The callback `fin_transfer_send_tokens_callback` only checks for refund when `is_ft_transfer_call = true` (i.e., when the transfer carries a non-empty `msg`). For the common case of plain token delivery (`msg` is empty), `is_refund_required` unconditionally returns `false`, meaning the callback **never inspects whether `ft_transfer` or `mint` actually succeeded**. If the token delivery fails, the transfer remains permanently in `finalised_transfers`, cannot be retried, and the user's funds are frozen forever.

---

### Finding Description

**Step 1 — Transfer is marked finalized before token delivery.**

In `process_fin_transfer_to_near`, `add_fin_transfer` is called first, committing the transfer ID to `finalised_transfers` in the same receipt as `fin_transfer_callback`. The token delivery (`send_tokens`) is then scheduled as a subsequent cross-contract call. [1](#0-0) 

Because NEAR's receipt model commits state changes in `fin_transfer_callback` before the chained `send_tokens` receipt executes, `add_fin_transfer` is **irrevocably committed** regardless of what happens in `send_tokens`.

**Step 2 — `send_tokens` dispatches `ft_transfer` or `mint` for the common (empty-msg) case.** [2](#0-1) [3](#0-2) 

Both paths set `is_ft_transfer_call = false` (because `msg` is empty), which is passed to `fin_transfer_send_tokens_callback`. [4](#0-3) 

**Step 3 — `is_refund_required` never checks the promise result for non-`ft_transfer_call` cases.** [5](#0-4) 

When `is_ft_transfer_call = false`, the function returns `false` unconditionally — it does **not** call `env::promise_result_checked`. The callback therefore cannot distinguish a successful `ft_transfer` from a failed one.

**Step 4 — On failure, the "success" path is taken.** [6](#0-5) 

Because `is_refund_required` returns `false`, `remove_fin_transfer` is never called, the fee is paid out, and `FinTransferEvent` is emitted — all as if the transfer succeeded. The transfer ID remains in `finalised_transfers` permanently.

The same issue applies to the wNEAR path: `near_withdraw_callback` panics on failure, but `add_fin_transfer` was already committed in a prior receipt, so the transfer is still stuck. [7](#0-6) 

---

### Impact Explanation

**Critical — permanent freezing of bridged funds.**

For native tokens (originated on NEAR, locked in the bridge on the way out): `unlock_tokens_if_needed` decreases the `locked_tokens` accounting, but the tokens remain in the bridge contract because `ft_transfer` failed. The transfer is in `finalised_transfers` and cannot be re-submitted. The tokens are permanently frozen in the bridge contract with no recovery path.

For deployed/bridged tokens: `mint` fails, no tokens are created for the user, yet the transfer is marked finalized. The user's cross-chain value is destroyed with no recourse.

---

### Likelihood Explanation

**Moderate.** The token delivery step (`ft_transfer` / `mint`) can fail in several realistic ways:

1. **Token contract paused** — many NEP-141 tokens implement a pause mechanism. If the token contract is paused between the storage-check receipt and the `ft_transfer` receipt, delivery fails silently.
2. **Recipient unregisters storage** — the storage check (`storage_balance_of`) and the `ft_transfer` execute in separate receipts. A recipient (or a griefing third party who controls the recipient account) can call `storage_unregister` in the window between the two receipts, causing `ft_transfer` to panic.
3. **Token contract bug or upgrade** — any panic in the token contract during `ft_transfer` or `mint` triggers the same silent-success path.

No special privilege is required; any inbound transfer to a NEAR recipient is affected.

---

### Recommendation

`fin_transfer_send_tokens_callback` must inspect the promise result for **all** token delivery paths, not only `ft_transfer_call`. Concretely:

1. Add a `#[callback_result]` (or use `env::promise_result_checked(0, …)`) to detect failure of `ft_transfer` / `mint` / `near_withdraw`.
2. On failure, call `remove_fin_transfer` (which removes the ID from `finalised_transfers`), revert lock actions, and emit `FailedFinTransferEvent` — mirroring the existing refund path — so the transfer can be retried.
3. Alternatively, move `add_fin_transfer` into `fin_transfer_send_tokens_callback` so it is only committed after confirmed delivery.

---

### Proof of Concept

1. A user bridges a native NEAR token from Ethereum back to NEAR (inbound transfer).
2. The token contract owner pauses the token contract.
3. A relayer calls `fin_transfer` with a valid proof.
4. `fin_transfer_callback` → `process_fin_transfer_to_near`:
   - `add_fin_transfer` commits the transfer ID to `finalised_transfers`. [8](#0-7) 
   - `unlock_tokens_if_needed` decreases `locked_tokens` accounting.
   - `send_tokens` dispatches `ft_transfer` on the paused token contract.
5. `ft_transfer` panics (contract is paused). The promise result is `Failed`.
6. `fin_transfer_send_tokens_callback` is called with `is_ft_transfer_call = false`.
7. `is_refund_required(false)` returns `false`. [9](#0-8) 
8. The else-branch executes: fee is minted to the relayer, `FinTransferEvent` is emitted. [10](#0-9) 
9. The transfer ID is permanently in `finalised_transfers`. Any retry of `fin_transfer` with the same proof panics with `TransferAlreadyFinalised`.
10. The user's tokens are frozen in the bridge contract with no recovery mechanism.

### Citations

**File:** near/omni-bridge/src/lib.rs (L1047-1052)
```rust
    pub fn near_withdraw_callback(&self, recipient: AccountId, amount: NearToken) -> Promise {
        match env::promise_result_checked(0, usize::MAX) {
            Ok(_) => Promise::new(recipient).transfer(amount),
            Err(_) => env::panic_str(BridgeError::NearWithdrawFailed.to_string().as_str()),
        }
    }
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

**File:** near/omni-bridge/src/lib.rs (L1875-1876)
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

**File:** near/omni-bridge/src/lib.rs (L2094-2101)
```rust
            ext_token::ext(token)
                .with_attached_deposit(deposit)
                .with_static_gas(MINT_TOKEN_GAS.saturating_add(ft_transfer_call_gas))
                .mint(
                    recipient,
                    amount,
                    (!msg.is_empty()).then(|| msg.to_string()),
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
