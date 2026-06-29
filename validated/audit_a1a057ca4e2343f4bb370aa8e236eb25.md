### Title
Silent `ft_transfer` Failure Permanently Freezes Bridged Funds on NEAR — (`File: near/omni-bridge/src/lib.rs`)

---

### Summary

When the NEAR `omni-bridge` finalizes an inbound transfer to a native (non-deployed) NEP-141 token recipient with an empty `msg`, it marks the transfer nonce as permanently used **before** the async `ft_transfer` cross-contract call. If that `ft_transfer` fails (e.g., because the token is paused), the callback `fin_transfer_send_tokens_callback` silently treats the failure as success and never removes the nonce from `finalised_transfers`. The user's source-chain funds are already locked/burned, and the destination transfer is irrecoverable.

---

### Finding Description

The NEAR `fin_transfer` flow for inbound transfers to NEAR recipients proceeds as follows:

**Step 1 — Nonce permanently consumed:**
`process_fin_transfer_to_near` calls `add_fin_transfer`, which inserts the `TransferId` into `finalised_transfers` and panics if it is already present. [1](#0-0) [2](#0-1) 

**Step 2 — Async token transfer dispatched:**
`send_tokens` is called. When `msg` is empty and the token is not wNEAR and not a deployed bridge token, it dispatches `ft_transfer` (a standard NEP-141 call). The callback is registered with `is_ft_transfer_call = !msg.is_empty()`, which evaluates to `false` for the common empty-message case. [3](#0-2) [4](#0-3) 

**Step 3 — Callback ignores promise failure:**
`fin_transfer_send_tokens_callback` calls `is_refund_required(is_ft_transfer_call)`. When `is_ft_transfer_call` is `false`, the function unconditionally returns `false` without inspecting the promise result at all. [5](#0-4) 

**Step 4 — Success path taken despite failure:**
Because `is_refund_required` returned `false`, the callback takes the "success" branch: it sends the fee (detached), logs `FinTransferEvent`, and returns. The nonce is **never** removed from `finalised_transfers`. [6](#0-5) 

The refund/recovery path — which calls `remove_fin_transfer` and `revert_lock_actions` — is only reachable when `is_ft_transfer_call = true` **and** the `ft_transfer_call` promise returns `U128(0)`. [7](#0-6) 

---

### Impact Explanation

If a native NEP-141 token registered with the bridge is paused at the moment `fin_transfer` is finalized:

1. The source-chain tokens (EVM/Solana/Starknet) are already locked or burned — they cannot be recovered from the source side.
2. The destination-nonce is permanently consumed in `finalised_transfers` — the transfer cannot be retried.
3. The `FinTransferEvent` is emitted as if the transfer succeeded — no on-chain signal of failure exists.
4. The recipient never receives tokens.

**Result: permanent, irrecoverable freezing of bridged user funds.** This matches the "Critical — permanent freezing of bridged funds" impact class.

---

### Likelihood Explanation

Many widely-used NEP-141 tokens on NEAR (e.g., USDC.e, USDT, and other stablecoin wrappers) implement a pause/blacklist mechanism. The bridge explicitly supports arbitrary native tokens via the `else` branch in `send_tokens`. Any relayer can trigger `fin_transfer` for a valid proof; if the token happens to be paused at that moment (even transiently), the silent-failure path is hit. No admin compromise is required — the attacker-controlled entry point is a valid cross-chain proof submitted by any relayer.

---

### Recommendation

In `fin_transfer_send_tokens_callback`, always inspect the promise result regardless of `is_ft_transfer_call`. When `is_ft_transfer_call = false` (i.e., `ft_transfer` was used), check `env::promise_result(0)` for `Failed`; if failed, call `remove_fin_transfer` and `revert_lock_actions` to restore state and emit `FailedFinTransferEvent`, allowing the transfer to be retried once the token is unpaused.

```rust
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    if is_ft_transfer_call {
        // existing logic
    } else {
        // NEW: check if the ft_transfer itself failed
        matches!(env::promise_result(0), PromiseResult::Failed)
    }
}
```

---

### Proof of Concept

1. Register a pausable NEP-141 token (e.g., a USDC wrapper) with the NEAR omni-bridge.
2. A user initiates a transfer from EVM → NEAR for that token; the EVM-side tokens are locked.
3. A relayer submits a valid proof to `fin_transfer` on NEAR.
4. `fin_transfer_callback` → `process_fin_transfer_to_near` → `add_fin_transfer` marks the nonce used.
5. The token issuer pauses the token (or it was already paused).
6. `send_tokens` dispatches `ft_transfer`; the token contract panics with "paused".
7. NEAR runtime calls `fin_transfer_send_tokens_callback` with `is_ft_transfer_call = false`.
8. `is_refund_required(false)` returns `false`; callback logs `FinTransferEvent` and exits.
9. `finalised_transfers` still contains the nonce — any retry of `fin_transfer` panics with `ERR_TRANSFER_ALREADY_FINALISED`.
10. User's funds are permanently frozen; no recovery path exists on either chain. [8](#0-7) [9](#0-8) [10](#0-9)

### Citations

**File:** near/omni-bridge/src/lib.rs (L1692-1747)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L1867-1978)
```rust
    #[allow(clippy::too_many_lines, clippy::ptr_arg)]
    fn process_fin_transfer_to_near(
        &mut self,
        recipient: AccountId,
        predecessor_account_id: &AccountId,
        transfer_message: TransferMessage,
        storage_deposit_actions: &Vec<StorageDepositAction>,
    ) -> Promise {
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());

        let token = self.get_token_id(&transfer_message.token);
        let fast_transfer = FastTransfer::from_transfer(transfer_message.clone(), token.clone());
        let fast_transfer_status = self.get_fast_transfer_status(&fast_transfer.id());

        let lock_actions = vec![self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        )];

        // If fast transfer happened, change recipient and fee recipient to the relayer that executed fast transfer
        let (recipient, msg, fee_recipient) = match fast_transfer_status {
            Some(status) => {
                require!(
                    !status.finalised,
                    BridgeError::FastTransferAlreadyFinalised.as_ref()
                );
                self.remove_fast_transfer(&fast_transfer.id());
                (status.relayer.clone(), String::new(), status.relayer)
            }
            None => (
                recipient,
                transfer_message.msg.clone(),
                predecessor_account_id.clone(),
            ),
        };

        let mut storage_deposit_action_index: usize = 0;
        require!(
            Self::check_storage_balance_result(
                (storage_deposit_action_index + 1)
                    .try_into()
                    .near_expect(BridgeError::Cast)
            ) && storage_deposit_actions[storage_deposit_action_index].account_id == recipient
                && storage_deposit_actions[storage_deposit_action_index].token_id == token,
            BridgeError::StorageRecipientOmitted.as_ref()
        );
        storage_deposit_action_index += 1;

        // One yoctoNear is required to send tokens to the recipient
        required_balance = required_balance.saturating_add(ONE_YOCTO);

        if transfer_message.fee.fee.0 > 0 {
            require!(
                Self::check_storage_balance_result(
                    (storage_deposit_action_index + 1)
                        .try_into()
                        .near_expect(BridgeError::Cast)
                ) && storage_deposit_actions[storage_deposit_action_index].account_id
                    == fee_recipient
                    && storage_deposit_actions[storage_deposit_action_index].token_id == token,
                BridgeError::StorageFeeRecipientOmitted.as_ref()
            );
            storage_deposit_action_index += 1;

            required_balance = required_balance.saturating_add(ONE_YOCTO);
        }

        if transfer_message.fee.native_fee.0 > 0 {
            let native_token_id = self.get_native_token_id(transfer_message.get_origin_chain());

            require!(
                Self::check_storage_balance_result(
                    (storage_deposit_action_index + 1)
                        .try_into()
                        .near_expect(BridgeError::Cast)
                ) && storage_deposit_actions[storage_deposit_action_index].account_id
                    == fee_recipient
                    && storage_deposit_actions[storage_deposit_action_index].token_id
                        == native_token_id,
                BridgeError::StorageNativeFeeRecipientOmitted.as_ref()
            );
        }

        self.update_storage_balance(
            predecessor_account_id.clone(),
            required_balance,
            env::attached_deposit(),
        );

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
    }
```

**File:** near/omni-bridge/src/lib.rs (L2056-2117)
```rust
    fn send_tokens(
        &self,
        token: AccountId,
        recipient: AccountId,
        amount: U128,
        msg: &str,
    ) -> Promise {
        let ft_transfer_call_gas = env::prepaid_gas()
            .saturating_sub(env::used_gas())
            .saturating_sub(SEND_TOKENS_CALLBACK_GAS) // TODO: not all send_tokens callbacks has the same gas.
            .saturating_sub(MINT_TOKEN_GAS)
            .min(FT_TRANSFER_CALL_GAS);

        let is_deployed_token = self.is_deployed_token(&token);

        if token == self.wnear_account_id && msg.is_empty() {
            // Unwrap wNEAR and transfer NEAR tokens
            ext_wnear_token::ext(self.wnear_account_id.clone())
                .with_static_gas(WNEAR_WITHDRAW_GAS)
                .with_attached_deposit(ONE_YOCTO)
                .near_withdraw(amount)
                .then(
                    Self::ext(env::current_account_id())
                        .with_static_gas(NEAR_WITHDRAW_CALLBACK_GAS)
                        .near_withdraw_callback(recipient, NearToken::from_yoctonear(amount.0)),
                )
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
        } else {
            require!(
                ft_transfer_call_gas >= MIN_FT_TRANSFER_CALL_GAS,
                BridgeError::NotEnoughGasForTokenTransfer(ft_transfer_call_gas).as_ref()
            );

            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(ft_transfer_call_gas)
                .ft_transfer_call(recipient, amount, None, msg.to_string())
        }
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
