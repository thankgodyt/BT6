### Title
Undetected `ft_transfer` Failure in `fin_transfer_send_tokens_callback` Causes Permanent Freezing of Bridged Funds — (`near/omni-bridge/src/lib.rs`)

---

### Summary

`fin_transfer_send_tokens_callback` never inspects the result of a plain `ft_transfer` promise. If the token contract rejects the transfer (e.g., due to a blacklist, pause, or any custom restriction), the bridge still marks the transfer as permanently finalised, decrements `locked_tokens`, and emits `FinTransferEvent` — while the tokens remain stuck in the bridge contract with no recovery path.

---

### Finding Description

`process_fin_transfer_to_near` sends tokens to the recipient via `send_tokens`, then chains `fin_transfer_send_tokens_callback`. [1](#0-0) 

Inside the callback, the only failure-detection mechanism is `is_refund_required(is_ft_transfer_call)`. [2](#0-1) 

`is_refund_required` is defined as: [3](#0-2) 

When `msg` is empty, `send_tokens` issues a plain `ft_transfer`: [4](#0-3) 

and the callback is invoked with `is_ft_transfer_call = false` (`!msg.is_empty()`). [5](#0-4) 

Because `is_ft_transfer_call` is `false`, `is_refund_required` unconditionally returns `false` — it never reads the promise result. The `else` branch executes regardless of whether `ft_transfer` succeeded or failed: it sends the fee and emits `FinTransferEvent`. [6](#0-5) 

The same blind spot exists for `ft_transfer_call` when the token contract itself panics (not just the receiver's `ft_on_transfer`): `is_refund_required` maps `Err(_)` to `false` ("Unexpected case: don't refund"). [7](#0-6) 

---

### Impact Explanation

When `ft_transfer` fails:

1. The token contract reverts — tokens remain in the bridge's balance.
2. `finalised_transfers` already contains the transfer ID (added in `add_fin_transfer` before `send_tokens` is called) — the transfer cannot be replayed.
3. `locked_tokens` was decremented by `unlock_tokens_if_needed` — the accounting is permanently off.
4. No recovery function exists.

The recipient's bridged funds are permanently frozen inside the bridge contract. This matches the allowed critical impact: **permanent freezing of bridged funds**.

---

### Likelihood Explanation

NEAR hosts NEP-141 tokens with custom transfer restrictions (blacklists, pauses). Any such token that is locked on NEAR and bridged outbound (NEAR → EVM) can trigger this path on the return leg (EVM → NEAR `fin_transfer`). The window between the storage-balance check (resolved in a prior receipt) and the `ft_transfer` execution (a subsequent receipt) is sufficient for a blacklisting event to occur. The attacker-controlled entry is the token issuer blacklisting the recipient, or a recipient contract that rejects transfers at the token-contract level.

---

### Recommendation

In `fin_transfer_send_tokens_callback`, explicitly check the promise result for the plain `ft_transfer` case (index 0) in addition to the `ft_transfer_call` case. If the promise failed, revert bridge state identically to the existing refund path: call `revert_lock_actions`, `remove_fin_transfer`, and emit `FailedFinTransferEvent`. This mirrors the fix recommended in the original report: handle the failed push gracefully rather than silently treating it as success.

---

### Proof of Concept

1. Deploy a NEP-141 token on NEAR with a blacklist (e.g., a USDC-style token).
2. Register the token with the Omni Bridge; bridge some amount to EVM (locking tokens in the bridge).
3. On EVM, initiate a return transfer back to NEAR with a NEAR recipient address.
4. Before the relayer calls `fin_transfer`, blacklist the recipient on the NEAR token contract.
5. Relayer calls `fin_transfer` with a valid proof. `process_fin_transfer_to_near` runs:
   - `add_fin_transfer` marks the transfer ID as finalised.
   - `unlock_tokens_if_needed` decrements `locked_tokens`.
   - `send_tokens` issues `ft_transfer(recipient, amount, None)` — the token contract panics (blacklisted), promise result is `Err`.
6. `fin_transfer_send_tokens_callback` is called with `is_ft_transfer_call = false`.
7. `is_refund_required(false)` returns `false`; the `else` branch fires, emitting `FinTransferEvent`.
8. Result: transfer ID consumed, `locked_tokens` decremented, tokens stuck in bridge, no recovery path. [8](#0-7)

### Citations

**File:** near/omni-bridge/src/lib.rs (L1690-1747)
```rust
    #[allow(clippy::needless_pass_by_value)]
    #[private]
    pub fn fin_transfer_send_tokens_callback(
        &mut self,
        #[serializer(borsh)] transfer_message: TransferMessage,
        #[serializer(borsh)] fee_recipient: &AccountId,
        #[serializer(borsh)] is_ft_transfer_call: bool,
        #[serializer(borsh)] storage_owner: &AccountId,
        #[serializer(borsh)] lock_actions: Vec<LockAction>,
    ) {
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

**File:** near/omni-bridge/src/lib.rs (L2102-2107)
```rust
        } else if msg.is_empty() {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
        } else {
```
