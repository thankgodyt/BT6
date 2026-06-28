### Title
Pending transfers permanently stuck when `add_factory` updates the factory address mid-flight - (File: `near/omni-bridge/src/lib.rs`)

### Summary

The `add_factory` function silently overwrites the registered factory address for a chain. Any transfer already stored in `pending_transfers` whose `claim_fee` proof references the old factory address will permanently revert with `UnknownFactory`, leaving the transfer irremovable from `pending_transfers` and the user's bridged funds frozen.

### Finding Description

**Root cause — `add_factory` overwrites without guard:**

```rust
#[access_control_any(roles(Role::DAO))]
pub fn add_factory(&mut self, address: OmniAddress) {
    self.factories.insert(&(&address).into(), &address);   // unconditional overwrite
}
```

There is no check for pending transfers before the overwrite occurs. [1](#0-0) 

**Failure point — `claim_fee_callback` validates against the *current* factory:**

```rust
require!(
    self.factories
        .get(&fin_transfer.emitter_address.get_chain())
        == Some(fin_transfer.emitter_address),
    BridgeError::UnknownFactory.as_ref()
);
```

The emitter address embedded in the proof was valid at the time the transfer was initiated, but after `add_factory` replaces it, every `claim_fee` call for in-flight transfers from the old factory reverts. [2](#0-1) 

**No escape hatch — there is no cancel or admin-remove function for `pending_transfers`:**

`remove_transfer_message` is only called inside `claim_fee_callback` (on success) and `sign_transfer_callback` (when fee is zero). A transfer whose `claim_fee` permanently reverts is irremovable. [3](#0-2) 

**Affected flows:**

1. **NEAR → Foreign chain** (`init_transfer` path): user tokens are locked/burned at `init_transfer`. If the destination-chain factory is updated before `claim_fee` succeeds, the transfer is stuck in `pending_transfers` indefinitely. Because `sign_transfer` carries no factory check, a rational relayer who knows `claim_fee` will revert has no economic incentive to call `sign_transfer`, leaving the user's locked/burned tokens permanently frozen. [4](#0-3) [5](#0-4) 

2. **Foreign → NEAR → Foreign** (`fin_transfer` + `sign_transfer` + `claim_fee` path): the transfer is stored in `pending_transfers` after `fin_transfer`. The same factory-update race applies; if the relayer does not complete the second leg, the user's source-chain funds are locked and the destination-chain tokens are never minted. [6](#0-5) 

### Impact Explanation

A factory update — a routine operational event (e.g., bridge contract redeployment on a foreign chain) — silently invalidates all in-flight `claim_fee` proofs for that chain. Because there is no mechanism to remove or rescue a stuck `pending_transfers` entry, and because `sign_transfer` provides no fee-claim guarantee after the factory changes, rational relayers will abandon incomplete transfers. The user's bridged tokens are permanently frozen inside the NEAR `omni-bridge` contract with no recovery path short of a contract upgrade.

### Likelihood Explanation

Factory addresses are expected to change over the bridge's lifetime (contract upgrades, chain migrations). The window between `init_transfer`/`fin_transfer` and `claim_fee` can span many blocks (MPC signing latency, cross-chain finality). Any factory update during that window triggers the freeze for all concurrent transfers to that chain.

### Recommendation

1. **Guard `add_factory` against in-flight transfers**: reject or queue the update if `pending_transfers` contains entries whose destination chain matches the factory being replaced.
2. **Snapshot the factory at transfer creation time**: store the expected emitter address inside `TransferMessage` and validate against it in `claim_fee_callback` instead of the live `factories` map.
3. **Add a DAO rescue function**: allow the DAO to forcibly complete or refund a stuck `pending_transfers` entry so users are not permanently harmed by operational changes.

### Proof of Concept

```
1. User calls ft_transfer_call → init_transfer stores transfer T in pending_transfers;
   user tokens are locked/burned.

2. DAO calls add_factory(new_eth_bridge_address) — legitimate upgrade.
   self.factories[ChainKind::Eth] now points to new_eth_bridge_address.

3. Relayer calls sign_transfer(T) — succeeds (no factory check here).
   MPC signature emitted.

4. Relayer submits signature to old Ethereum bridge (still live, still valid).
   FinTransfer event emitted by old_eth_bridge_address.

5. Relayer calls claim_fee with proof of that FinTransfer event.
   claim_fee_callback executes:
     self.factories.get(ChainKind::Eth) == Some(new_eth_bridge_address)
     fin_transfer.emitter_address          == old_eth_bridge_address
     → require! fails → ERR_UNKNOWN_FACTORY → revert.

6. Transfer T remains in pending_transfers forever.
   No cancel/refund path exists.
   User's tokens are permanently frozen.

Alternate (no sign_transfer called):
   After step 2, relayer observes claim_fee will fail → skips sign_transfer entirely.
   User tokens locked/burned, never reach destination. Same permanent freeze.
``` [1](#0-0) [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L447-521)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L523-618)
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
```

**File:** near/omni-bridge/src/lib.rs (L1054-1063)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise {
        self.verify_proof(args.chain_kind, args.prover_args).then(
            Self::ext(env::current_account_id())
                .with_attached_deposit(env::attached_deposit())
                .with_static_gas(CLAIM_FEE_CALLBACK_GAS)
                .claim_fee_callback(&env::predecessor_account_id()),
        )
```

**File:** near/omni-bridge/src/lib.rs (L1087-1092)
```rust
        require!(
            self.factories
                .get(&fin_transfer.emitter_address.get_chain())
                == Some(fin_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1501-1504)
```rust
    #[access_control_any(roles(Role::DAO))]
    pub fn add_factory(&mut self, address: OmniAddress) {
        self.factories.insert(&(&address).into(), &address);
    }
```

**File:** near/omni-bridge/src/lib.rs (L1980-2054)
```rust
    fn process_fin_transfer_to_other_chain(
        &mut self,
        predecessor_account_id: AccountId,
        transfer_message: TransferMessage,
    ) {
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());
        let token = self.get_token_id(&transfer_message.token);

        if transfer_message.recipient.is_utxo_chain() {
            let btc_account_id =
                self.get_utxo_chain_token(transfer_message.get_destination_chain());
            require!(
                token == btc_account_id,
                BridgeError::NativeTokenRequiredForChain.as_ref()
            );
        }

        self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        );
        self.lock_tokens_if_needed(
            transfer_message.get_destination_chain(),
            &token,
            transfer_message.fee.fee.into(),
        );

        let fast_transfer = FastTransfer::from_transfer(transfer_message.clone(), token.clone());
        let recipient = if let Some(status) = self.get_fast_transfer_status(&fast_transfer.id()) {
            require!(
                !status.finalised,
                BridgeError::FastTransferAlreadyFinalised.as_ref()
            );
            Some(status.relayer)
        } else {
            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token,
                transfer_message
                    .amount_without_fee()
                    .near_expect(BridgeError::InvalidFee),
            );

            None
        };

        // If fast transfer happened, send tokens to the relayer that executed fast transfer
        if let Some(relayer) = recipient {
            self.send_tokens(
                token,
                relayer,
                U128(
                    transfer_message
                        .amount_without_fee()
                        .near_expect(BridgeError::InvalidFee),
                ),
                "",
            )
            .detach();
            self.mark_fast_transfer_as_finalised(&fast_transfer.id());
        } else {
            required_balance = self
                .add_transfer_message(transfer_message.clone(), predecessor_account_id.clone())
                .saturating_add(required_balance);
        }

        self.update_storage_balance(
            predecessor_account_id,
            required_balance,
            env::attached_deposit(),
        );

        env::log_str(&OmniBridgeEvent::FinTransferEvent { transfer_message }.to_log_string());
    }
```

**File:** near/omni-bridge/src/lib.rs (L2194-2211)
```rust
    fn remove_transfer_message(&mut self, transfer_id: TransferId) -> TransferMessage {
        let storage_usage = env::storage_usage();
        let transfer = self
            .pending_transfers
            .remove(&transfer_id)
            .map(storage::TransferMessageStorage::into_main)
            .near_expect(BridgeError::TransferNotExist);

        let refund =
            env::storage_byte_cost().saturating_mul((storage_usage - env::storage_usage()).into());

        if let Some(mut storage) = self.accounts_balances.get(&transfer.owner) {
            storage.available = storage.available.saturating_add(refund);
            self.accounts_balances.insert(&transfer.owner, &storage);
        }

        transfer.message
    }
```
