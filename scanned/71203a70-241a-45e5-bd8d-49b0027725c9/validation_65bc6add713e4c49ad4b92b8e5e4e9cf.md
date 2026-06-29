### Title
`is_refund_required` Silently Treats `ft_transfer` Failure as Success, Permanently Finalizing Transfer Without Delivering Tokens — (`near/omni-bridge/src/lib.rs`)

### Summary

In `fin_transfer_send_tokens_callback`, the helper `is_refund_required` returns `false` in two cases where the underlying token delivery actually failed: (1) whenever `is_ft_transfer_call` is `false` (i.e., `msg` is empty, so `ft_transfer` was used), regardless of the promise outcome; and (2) when `is_ft_transfer_call` is `true` but the promise result is `Err`. In both cases the transfer ID is left permanently in `finalised_transfers`, locked-token accounting is not restored, and the recipient never receives tokens. There is no DAO escape hatch or retry mechanism.

### Finding Description

The flow for an inbound transfer to a NEAR recipient is:

1. `fin_transfer_callback` → `process_fin_transfer_to_near`
2. `add_fin_transfer` inserts the transfer ID into `finalised_transfers` (replay guard).
3. `unlock_tokens_if_needed` decrements the locked-token counter for the origin chain.
4. `send_tokens` dispatches either `ft_transfer` (empty `msg`) or `ft_transfer_call` (non-empty `msg`).
5. `fin_transfer_send_tokens_callback` is chained as the resolution callback. [1](#0-0) [2](#0-1) [3](#0-2) 

Inside the resolution callback, `is_refund_required` decides whether to revert:

```rust
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    if is_ft_transfer_call {
        match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
            Ok(value) => { ... amount.0 == 0 }
            // Unexpected case: don't refund   ← BUG
            Err(_) => false,
        }
    } else {
        // Not ft_transfer_call: don't refund  ← BUG
        false
    }
}
``` [4](#0-3) 

**Bug path A — `ft_transfer` (empty `msg`):** `is_ft_transfer_call` is `false`, so `is_refund_required` unconditionally returns `false`. If `ft_transfer` fails (promise `Err`), the callback takes the `else` branch: it pays the fee to the relayer and emits `FinTransferEvent` as if the transfer succeeded.

**Bug path B — `ft_transfer_call` / `mint` protocol-level failure:** If the token contract panics before `ft_resolve_transfer` can return a value (e.g., the token is paused, the recipient is blacklisted, or the deployed-token `mint` call fails), the promise result is `Err`. `is_refund_required` returns `false` for the same reason.

In both cases the `else` branch runs:

```rust
} else {
    // Send fee to the fee recipient
    ...
    env::log_str(&OmniBridgeEvent::FinTransferEvent { transfer_message }.to_log_string());
}
``` [5](#0-4) 

The correct revert path (`remove_fin_transfer`, `revert_lock_actions`) is never reached: [6](#0-5) 

The same flaw is present in `resolve_utxo_fin_transfer` and `resolve_fast_transfer`, which both delegate to the same `is_refund_required`: [7](#0-6) [8](#0-7) 

### Impact Explanation

After a failed `ft_transfer`:

- The transfer ID remains in `finalised_transfers` — replay protection prevents any retry.
- The locked-token counter for the origin chain has already been decremented by `unlock_tokens_if_needed` and is never restored.
- For native (non-deployed) tokens: the tokens remain stranded inside the bridge contract with no withdrawal path.
- For deployed (bridged) tokens: the mint never happened; the source-chain tokens are permanently locked.
- The relayer is paid a fee for a transfer that never completed.

This constitutes **permanent freezing of bridged funds** — the exact impact class listed in the allowed scope.

### Likelihood Explanation

`ft_transfer` can fail in realistic production conditions:

- Token contracts that implement transfer restrictions (blacklists, compliance pauses, per-account limits) — common for regulated or enterprise tokens.
- A token contract that is administratively paused between the storage-deposit check and the actual transfer.
- For deployed `omni-token` via `mint`: if the token contract itself is paused or the bridge's mint authority is revoked.

The bridge is designed to support arbitrary NEP-141 tokens, so encountering a token with transfer restrictions is a foreseeable, non-hypothetical scenario. The user whose transfer fails has no recourse.

### Recommendation

`is_refund_required` must inspect the promise result even when `is_ft_transfer_call` is `false`:

```rust
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    // Always check whether the promise succeeded
    match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
        Err(_) => true,   // promise failed → revert
        Ok(value) if is_ft_transfer_call => {
            near_sdk::serde_json::from_slice::<U128>(&value)
                .map_or(false, |a| a.0 == 0)
        }
        Ok(_) => false,   // ft_transfer succeeded
    }
}
```

This ensures that any protocol-level failure of `ft_transfer` or `ft_transfer_call` triggers the revert path (`remove_fin_transfer`, `revert_lock_actions`), restoring the locked-token counter and allowing the transfer to be retried.

### Proof of Concept

1. A user on Ethereum initiates a transfer of a token that has a recipient blacklist. The token is registered with the bridge.
2. The relayer calls `fin_transfer` on NEAR with an empty `msg` (plain transfer, no callback).
3. `process_fin_transfer_to_near` runs: `add_fin_transfer` marks the ID as used; `unlock_tokens_if_needed` decrements the locked counter.
4. `send_tokens` calls `ft_transfer(recipient, amount, None)` on the token contract.
5. The token contract's `ft_transfer` panics because the recipient is blacklisted → promise result is `Err`.
6. `fin_transfer_send_tokens_callback` is invoked with `is_ft_transfer_call = false`.
7. `is_refund_required(false)` returns `false` unconditionally.
8. The `else` branch fires: fee is paid to the relayer, `FinTransferEvent` is emitted.
9. The transfer ID is permanently in `finalised_transfers`; `revert_lock_actions` is never called.
10. The recipient has received nothing. The Ethereum tokens are permanently locked. No retry is possible.

### Citations

**File:** near/omni-bridge/src/lib.rs (L895-912)
```rust
    #[private]
    pub fn resolve_fast_transfer(
        &mut self,
        token_id: &AccountId,
        fast_transfer_id: &FastTransferId,
        amount: U128,
        is_ft_transfer_call: bool,
    ) -> U128 {
        // Burn the tokens to ensure the locked tokens are not double-minted
        self.burn_tokens_if_needed(token_id.clone(), amount);

        if Self::is_refund_required(is_ft_transfer_call) {
            self.remove_fast_transfer(fast_transfer_id);
            amount
        } else {
            U128(0)
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L1014-1043)
```rust
    #[allow(clippy::needless_pass_by_value)]
    #[private]
    pub fn resolve_utxo_fin_transfer(
        &mut self,
        token_id: AccountId,
        amount: U128,
        utxo_fin_transfer_msg: UtxoFinTransferMsg,
        origin_chain: ChainKind,
        storage_owner: &AccountId,
    ) -> U128 {
        let is_ft_transfer_call = !utxo_fin_transfer_msg.msg.is_empty();
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
