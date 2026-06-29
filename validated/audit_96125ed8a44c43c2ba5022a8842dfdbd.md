### Title
Missing Cancel Mechanism for Pending Outbound Transfers Permanently Freezes User Funds - (File: near/omni-bridge/src/lib.rs)

### Summary
The NEAR Omni Bridge has no `cancel_transfer` function for outbound (NEAR → Foreign) transfers. Once a user initiates a transfer via `ft_on_transfer`, their tokens are locked or burned on NEAR and stored in `pending_transfers`. If no trusted relayer ever calls `sign_transfer` — or if MPC signing fails persistently — the user has no self-sovereign path to reclaim their funds. This is a direct analog to the Connext/BridgeFacet missing cancel function: users are permanently dependent on relayer liveness with no escape hatch.

---

### Finding Description

The outbound transfer lifecycle in `near/omni-bridge/src/lib.rs` is:

1. **User** calls `ft_on_transfer` with an `InitTransfer` message.
2. `init_transfer` is called internally, which increments `current_origin_nonce`, constructs a `TransferMessage`, and calls `init_transfer_internal` — which locks or burns the user's tokens and inserts the message into `pending_transfers`.
3. A **trusted relayer** must call `sign_transfer` to obtain an MPC signature.
4. The relayer submits the signed transaction to the destination chain. [1](#0-0) 

After step 2, the user's tokens are gone from their account. The only public functions that touch `pending_transfers` are:

- `sign_transfer` — restricted to trusted relayers via `#[trusted_relayer]`
- `update_transfer_fee` — allows the sender to *increase* the fee to attract relayers, but does not return tokens
- `sign_transfer_callback` — removes the transfer only after a successful MPC signature when fee is zero [2](#0-1) [3](#0-2) 

There is no `cancel_transfer` or equivalent function anywhere in the contract. The `storage_unregister` function explicitly *blocks* unregistration while pending transfers exist, confirming the protocol is aware of this state but provides no exit: [4](#0-3) 

The `update_transfer_fee` function only allows fee increases (never cancellation), and only the sender can raise the token fee: [5](#0-4) 

---

### Impact Explanation

If a trusted relayer never calls `sign_transfer` for a given `TransferId` — due to relayer downtime, a bug, a policy decision, or the relayer set being empty — the user's tokens remain locked/burned on NEAR indefinitely. The user cannot:

- Cancel the transfer and recover their tokens.
- Force a relayer to process it (they can only raise the fee).
- Unregister their storage account while the transfer is pending.

This constitutes **permanent freezing of bridged funds**, which is within the critical impact scope.

---

### Likelihood Explanation

The `sign_transfer` entry point is gated by `#[trusted_relayer]`, meaning only accounts approved by `Role::DAO` or `Role::RelayerManager` can process transfers. [6](#0-5) 

Any of the following realistic conditions causes permanent fund loss with no user recourse:

- The relayer set is temporarily or permanently empty.
- All active relayers go offline or are decommissioned.
- A relayer selectively ignores specific transfers (e.g., small amounts, specific tokens, or specific recipients).
- MPC signing fails persistently for a transfer (the callback silently drops the transfer without refunding).

The MPC signing failure path in `sign_transfer_callback` is particularly notable: if `call_result` is `Err`, the function does nothing — no refund, no removal, no event: [3](#0-2) 

---

### Recommendation

Implement a `cancel_transfer` function that:

1. Verifies the caller is the original `sender` of the transfer (stored in `TransferMessage.sender`).
2. Optionally enforces a minimum waiting period (e.g., after N blocks) to prevent griefing of in-flight transfers.
3. Removes the transfer from `pending_transfers`.
4. Unlocks or re-mints the user's tokens back to their account.
5. Refunds any native fee deposited.

This mirrors the fix applied in Connext PR 2456 and gives users a self-sovereign exit path independent of relayer liveness.

---

### Proof of Concept

1. Alice calls `ft_on_transfer` on the NEAR bridge contract, transferring 1000 USDC with `InitTransfer { recipient: "eth:0xAlice", fee: 0, native_token_fee: 0, ... }`.
2. `init_transfer` runs: `current_origin_nonce` increments, 1000 USDC is burned/locked, and the `TransferMessage` is inserted into `pending_transfers` under `TransferId { origin_chain: Near, origin_nonce: N }`.
3. The only trusted relayer goes offline permanently (or selectively ignores Alice's transfer).
4. Alice attempts `update_transfer_fee` to raise the fee — no relayer responds.
5. Alice attempts `storage_unregister` — it panics with `BridgeError::StoragePendingTransfers` because her transfer is still pending.
6. Alice has no `cancel_transfer` function to call. Her 1000 USDC is permanently frozen in the bridge contract with no on-chain recovery path. [7](#0-6) [8](#0-7)

### Citations

**File:** near/omni-bridge/src/lib.rs (L244-249)
```rust

#[trusted_relayer(
    bypass_roles(Role::DAO, Role::UnrestrictedRelayer),
    manager_roles(Role::DAO, Role::RelayerManager),
    config_roles(Role::DAO)
)]
```

**File:** near/omni-bridge/src/lib.rs (L388-436)
```rust
    pub fn update_transfer_fee(&mut self, transfer_id: TransferId, fee: UpdateFee) {
        match fee {
            UpdateFee::Fee(fee) => {
                let mut transfer = self.get_transfer_message_storage(transfer_id);

                require!(
                    transfer.message.origin_transfer_id.is_none(),
                    BridgeError::UpdateFeeNotAllowedForTransfer.as_ref()
                );

                let current_fee = transfer.message.fee;
                require!(
                    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
                    BridgeError::InvalidFee.as_ref()
                );

                require!(
                    fee.fee == current_fee.fee
                        || OmniAddress::Near(env::predecessor_account_id())
                            == transfer.message.sender,
                    BridgeError::SenderCanUpdateTokenFeeOnly.as_ref()
                );

                let diff_native_fee = fee
                    .native_fee
                    .0
                    .checked_sub(current_fee.native_fee.0)
                    .near_expect(BridgeError::LowerFee);

                require!(
                    NearToken::from_yoctonear(diff_native_fee) == env::attached_deposit(),
                    BridgeError::InvalidAttachedDeposit.as_ref()
                );

                transfer.message.fee = fee;
                self.insert_raw_transfer(transfer.message.clone(), transfer.owner);

                env::log_str(
                    &OmniBridgeEvent::UpdateFeeEvent {
                        transfer_message: transfer.message,
                    }
                    .to_log_string(),
                );
            }
            UpdateFee::Proof(_) => {
                env::panic_str(BridgeError::UnsupportedFeeUpdateProof.to_string().as_str())
            }
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L444-521)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_transfer(
        &mut self,
        transfer_id: TransferId,
        fee_recipient: Option<AccountId>,
        fee: &Option<Fee>,
    ) -> Promise {
        let transfer_message = self.get_transfer_message(transfer_id);

        if let Some(fee) = &fee {
            require!(
                &transfer_message.fee == fee,
                BridgeError::InvalidFee.as_ref()
            );
        }

        let token_address = self
            .get_token_address(
                transfer_message.get_destination_chain(),
                self.get_token_id(&transfer_message.token),
            )
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });

        let decimals = self
            .token_decimals
            .get(&token_address)
            .near_expect(BridgeError::TokenDecimalsNotFound);
        let amount_to_transfer = Self::normalize_amount(
            transfer_message
                .amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals,
        );

        require!(
            amount_to_transfer > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );

        let message = DestinationChainMsg::from_json(&transfer_message.msg)
            .and_then(|s| s.destination_msg())
            .unwrap_or_default();

        let transfer_payload = TransferMessagePayload {
            prefix: PayloadType::TransferMessage,
            destination_nonce: transfer_message.destination_nonce,
            transfer_id,
            token_address,
            amount: U128(amount_to_transfer),
            recipient: transfer_message.recipient,
            fee_recipient,
            message,
        };

        let payload = near_sdk::env::keccak256_array(
            transfer_payload
                .encode_hashable()
                .near_expect(BridgeError::Borsh),
        );

        ext_signer::ext(self.mpc_signer.clone())
            .with_static_gas(MPC_SIGNING_GAS)
            .with_attached_deposit(env::attached_deposit())
            .sign(SignRequest {
                payload,
                path: SIGN_PATH.to_owned(),
                key_version: 0,
            })
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(SIGN_TRANSFER_CALLBACK_GAS)
                    .sign_transfer_callback(transfer_payload, &transfer_message.fee),
            )
    }
```

**File:** near/omni-bridge/src/lib.rs (L523-619)
```rust
    fn init_transfer(
        &mut self,
        sender_id: AccountId,
        signer_id: AccountId,
        token_id: AccountId,
        amount: U128,
        init_transfer_msg: InitTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );

        self.current_origin_nonce += 1;
        let destination_nonce =
            self.get_next_destination_nonce(init_transfer_msg.get_destination_chain());

        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount,
            recipient: init_transfer_msg.recipient,
            fee: Fee {
                fee: init_transfer_msg.fee,
                native_fee: init_transfer_msg.native_token_fee,
            },
            sender: OmniAddress::Near(sender_id),
            msg: init_transfer_msg.msg.map(String::from).unwrap_or_default(),
            destination_nonce,
            origin_transfer_id: None,
        };
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );

        let required_storage_balance =
            self.required_balance_for_init_transfer_message(transfer_message.clone());

        let message_storage_account_id = transfer_message
            .calculate_storage_account_id(init_transfer_msg.external_id.map(String::from));

        // Choose storage payer or whether to yield execution until storage is available
        if self
            .try_to_transfer_balance_from_message_account(
                &message_storage_account_id,
                NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
                &signer_id,
                required_storage_balance,
            )
            .is_ok()
            || (self.has_storage_balance(
                &signer_id,
                required_storage_balance.saturating_add(NearToken::from_yoctonear(
                    init_transfer_msg.native_token_fee.0,
                )),
            ) && (init_transfer_msg.native_token_fee.0 == 0
                || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
        {
            PromiseOrPromiseIndexOrValue::Value(
                self.init_transfer_internal(transfer_message, signer_id),
            )
        } else {
            let promise_index = env::promise_yield_create(
                "init_transfer_resume",
                json!({
                    "transfer_message": transfer_message,
                    "message_storage_account_id": message_storage_account_id,
                    "storage_owner": signer_id,
                })
                .to_string()
                .as_bytes(),
                INIT_TRANSFER_RESUME_GAS,
                GasWeight(0),
                PROMISE_REGISTER_ID,
            );

            let yield_id: CryptoHash = env::read_register(PROMISE_REGISTER_ID)
                .near_expect(BridgeError::ReadPromiseRegister)
                .try_into()
                .near_expect(BridgeError::ReadPromiseYieldId);

            let required_storage_balance = self.add_promise(&message_storage_account_id, &yield_id);

            self.update_storage_balance(
                env::current_account_id(),
                required_storage_balance,
                NearToken::from_yoctonear(0),
            );

            env::log_str(&format!(
                "Yield init transfer until storage is available at {message_storage_account_id}"
            ));

            PromiseOrPromiseIndexOrValue::PromiseIndex(promise_index)
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L648-668)
```rust
    #[private]
    pub fn sign_transfer_callback(
        &mut self,
        #[callback_result] call_result: Result<SignatureResponse, PromiseError>,
        #[serializer(borsh)] message_payload: TransferMessagePayload,
        #[serializer(borsh)] fee: &Fee,
    ) {
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }

            env::log_str(
                &OmniBridgeEvent::SignTransferEvent {
                    signature,
                    message_payload,
                }
                .to_log_string(),
            );
        }
    }
```

**File:** near/omni-bridge/src/storage.rs (L214-237)
```rust
    #[payable]
    pub fn storage_unregister(&mut self, force: Option<bool>) -> bool {
        assert_one_yocto();
        let account_id = env::predecessor_account_id();
        let Some(storage) = self.storage_balance_of(&account_id) else {
            return false;
        };

        if !force.unwrap_or_default() {
            require!(
                storage.total.saturating_sub(storage.available)
                    == self.required_balance_for_account(),
                BridgeError::StoragePendingTransfers.as_ref()
            );
        }

        self.accounts_balances.remove(&account_id);

        let refund = self
            .required_balance_for_account()
            .saturating_add(storage.available);
        Promise::new(account_id).transfer(refund).detach();
        true
    }
```
