### Title
Silent `ft_transfer` Failure Permanently Freezes Bridged Funds — (`near/omni-bridge/src/lib.rs`)

### Summary

`fin_transfer_send_tokens_callback` does not check whether the underlying `ft_transfer` (plain, non-call) to the recipient actually succeeded. When that transfer fails at the NEAR runtime level (e.g., recipient blacklisted in USDC/USDT, token contract paused), the bridge silently treats the transfer as successful: the transfer ID remains permanently in `finalised_transfers`, `locked_tokens` accounting is already decremented, the fee is paid to the relayer, and `FinTransferEvent` is emitted — while the user's tokens are permanently frozen inside the bridge contract with no recovery path.

### Finding Description

The `is_refund_required` helper only handles one specific case: `ft_transfer_call` where the receiver's `ft_on_transfer` returns `"0"` (all tokens rejected). For every other failure mode — including a plain `ft_transfer` promise failure and an `ft_transfer_call` promise-level failure — it returns `false`. [1](#0-0) 

`fin_transfer_send_tokens_callback` branches entirely on this boolean. When `is_refund_required` returns `false`, the callback unconditionally pays the fee and emits `FinTransferEvent` without inspecting the promise result of `send_tokens`. [2](#0-1) 

The refund/revert path — which calls `burn_tokens_if_needed`, `revert_lock_actions`, and `remove_fin_transfer` — is never reached for a plain `ft_transfer` failure. [3](#0-2) 

`send_tokens` uses plain `ft_transfer` (not `ft_transfer_call`) whenever `msg` is empty and the token is a non-deployed, non-wNEAR asset. [4](#0-3) 

The transfer is already marked finalized and locked-token accounting already decremented **before** `send_tokens` is called, inside `process_fin_transfer_to_near`. [5](#0-4) 

Because `remove_fin_transfer` is never called in the non-refund path, the transfer ID stays in `finalised_transfers` forever, making any retry impossible. [6](#0-5) 

### Impact Explanation

When `ft_transfer` to the recipient fails:

1. The transfer is permanently finalized — it cannot be re-submitted.
2. `locked_tokens` for the origin chain is already decremented — the accounting no longer reflects the actual token balance held by the bridge.
3. The bridge contract retains the tokens (since `ft_transfer` panicked and the tokens never left), but there is no mechanism to recover or redistribute them.
4. The relayer still receives its fee, and `FinTransferEvent` is emitted, making off-chain observers believe the transfer succeeded.

The user's bridged funds are permanently frozen inside the bridge contract. This matches the allowed impact: **permanent freezing of bridged funds**.

### Likelihood Explanation

The bridge is designed to support any NEP-141 token. Tokens such as USDC and USDT on NEAR implement operator-controlled blacklists and pause mechanisms. A recipient account can be blacklisted between the time the source-chain transfer is initiated and the time the relayer submits the proof on NEAR. Regulatory blacklisting of addresses is a documented, real-world event. No privileged access is required on the bridge side; the trigger is entirely within the token contract's normal operation.

### Recommendation

In `fin_transfer_send_tokens_callback`, check the promise result regardless of whether `is_ft_transfer_call` is set. If the `send_tokens` promise failed (i.e., `env::promise_result_checked(0, …)` returns `Err`), execute the same revert path that is currently used for the `ft_transfer_call`-returns-zero case: burn minted tokens if needed, revert lock actions, remove the fin-transfer record, and emit `FailedFinTransferEvent`. This mirrors the existing refund logic and ensures no transfer is silently lost.

### Proof of Concept

1. A user locks 1000 USDC on Ethereum and initiates a transfer to a NEAR recipient address.
2. Before the relayer submits the proof, the NEAR recipient address is blacklisted by the USDC contract operator.
3. The relayer calls `fin_transfer` with a valid proof.
4. `process_fin_transfer_to_near` runs: `add_fin_transfer` marks the transfer finalized; `unlock_tokens_if_needed` decrements `locked_tokens[Eth][usdc.near]` by 1000.
5. `send_tokens` issues `ft_transfer(recipient, 1000)` to `usdc.near`. The USDC contract panics because the recipient is blacklisted. The promise result is `Failed`.
6. `fin_transfer_send_tokens_callback` is called with `is_ft_transfer_call = false`.
7. `is_refund_required(false)` returns `false` unconditionally.
8. The `else` branch executes: fee is minted/transferred to the relayer; `FinTransferEvent` is emitted.
9. The transfer ID is permanently in `finalised_transfers`. `locked_tokens[Eth][usdc.near]` is 0. The bridge contract still holds 1000 USDC. The user's funds are irrecoverable. [1](#0-0) [7](#0-6)

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

**File:** near/omni-bridge/src/lib.rs (L2322-2333)
```rust
    fn remove_fin_transfer(&mut self, transfer_id: &TransferId, storage_owner: &AccountId) {
        let storage_usage = env::storage_usage();
        self.finalised_transfers.remove(transfer_id);

        let refund =
            env::storage_byte_cost().saturating_mul((storage_usage - env::storage_usage()).into());

        if let Some(mut storage) = self.accounts_balances.get(storage_owner) {
            storage.available = storage.available.saturating_add(refund);
            self.accounts_balances.insert(storage_owner, &storage);
        }
    }
```
