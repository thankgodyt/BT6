### Title
Pause Bypass via Async `fin_transfer_callback` Allows Token Minting/Unlocking When Contract Is Paused — (`near/omni-bridge/src/lib.rs`)

---

### Summary

The `omni-bridge` NEAR contract enforces a pause guard on `fin_transfer`, the public entry point for finalizing inbound cross-chain transfers. However, the asynchronous callback `fin_transfer_callback`, which performs the actual token minting or unlocking, carries no pause check. Because NEAR promise callbacks execute in a later receipt — potentially in a different block — the contract can be paused between the two steps, and the callback will still complete the transfer, bypassing the intended pause protection.

---

### Finding Description

`fin_transfer` is decorated with `#[pause(except(roles(Role::DAO)))]`, preventing non-DAO callers from initiating new inbound finalizations while the contract is paused. [1](#0-0) 

It schedules a cross-contract proof-verification call and chains `fin_transfer_callback` as the continuation: [2](#0-1) 

`fin_transfer_callback` is marked only `#[private]` — it has **no pause check**: [3](#0-2) 

Inside the callback, `process_fin_transfer_to_near` is called for NEAR-bound transfers, which mints or transfers tokens to the recipient. For transfers routed to other chains, `process_fin_transfer_to_other_chain` is called, which records a new outbound transfer message. Both are security-sensitive state changes that the pause mechanism is intended to block.

The same pattern exists for `deploy_token_callback` (called from the paused `deploy_token`) and `bind_token_callback` (called from the paused `bind_token`), but `fin_transfer_callback` is the highest-impact instance because it directly controls token issuance. [4](#0-3) [5](#0-4) 

---

### Impact Explanation

An attacker or relayer who submits a `fin_transfer` call just before the contract is paused (or whose in-flight call races with a pause transaction) will have their `fin_transfer_callback` execute regardless of the pause state. This causes the bridge to mint or release bridged tokens to the recipient even during a security incident for which the pause was activated. This constitutes an **unauthorized pause bypass** that can result in **loss or unauthorized minting of bridged funds** during a window when the protocol is supposed to be fully halted.

---

### Likelihood Explanation

NEAR promise callbacks execute in a subsequent receipt, which may land in a different block from the originating call. A `PauseManager` pausing the contract in response to a detected exploit cannot retroactively cancel already-scheduled callbacks. Any `fin_transfer` call submitted before the pause transaction is confirmed will produce a callback that bypasses the pause. This is a realistic race condition requiring no special attacker capability beyond submitting a normal bridge finalization. [6](#0-5) 

---

### Recommendation

Add a pause guard at the start of `fin_transfer_callback`. Using the `near-plugins` `Pausable` trait already imported by the contract, check `self.is_paused()` (or apply the `#[pause]` macro) before processing the prover result. If the contract is paused, the callback should refund any attached deposit and return without minting or recording any state change. Apply the same fix to `deploy_token_callback` and `bind_token_callback`. [7](#0-6) 

---

### Proof of Concept

1. The bridge is operating normally. A relayer submits `fin_transfer` for a large inbound transfer (e.g., 1 000 000 USDC from Ethereum to NEAR). The call passes the pause check and schedules `verify_proof` → `fin_transfer_callback`.
2. In the same or next block, a `PauseManager` detects an exploit and calls `pa_pause` to halt the contract.
3. In the following block, the NEAR runtime delivers the `fin_transfer_callback` receipt. Because `fin_transfer_callback` has no pause check, it reads the prover result, validates the factory, and calls `process_fin_transfer_to_near`, which mints 1 000 000 USDC to the recipient.
4. The pause intended to freeze all bridge operations has been bypassed; tokens have been minted during the incident window. [8](#0-7)

### Citations

**File:** near/omni-bridge/src/lib.rs (L209-212)
```rust
#[near(contract_state)]
#[derive(Pausable, Upgradable, PanicOnDefault)]
#[access_control(role_type(Role))]
#[pausable(manager_roles(Role::PauseManager))]
```

**File:** near/omni-bridge/src/lib.rs (L670-746)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn fin_transfer(&mut self, #[serializer(borsh)] args: FinTransferArgs) -> Promise {
        require!(
            args.storage_deposit_actions.len() <= 3,
            BridgeError::InvalidStorageAccountsLen.as_ref()
        );
        let mut main_promise = self.verify_proof(args.chain_kind, args.prover_args);

        let mut attached_deposit = env::attached_deposit();

        for action in &args.storage_deposit_actions {
            main_promise =
                main_promise.and(Self::check_or_pay_ft_storage(action, &mut attached_deposit));
        }

        main_promise.then(
            Self::ext(env::current_account_id())
                .with_attached_deposit(attached_deposit)
                .with_static_gas(FIN_TRANSFER_CALLBACK_GAS)
                .fin_transfer_callback(
                    &args.storage_deposit_actions,
                    env::predecessor_account_id(),
                ),
        )
    }

    #[private]
    #[payable]
    pub fn fin_transfer_callback(
        &mut self,
        #[serializer(borsh)] storage_deposit_actions: &Vec<StorageDepositAction>,
        #[serializer(borsh)] predecessor_account_id: AccountId,
    ) -> PromiseOrValue<Nonce> {
        let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };
        require!(
            self.factories
                .get(&init_transfer.emitter_address.get_chain())
                == Some(init_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        let decimals = self
            .token_decimals
            .get(&init_transfer.token)
            .near_expect(BridgeError::TokenDecimalsNotFound);

        let destination_nonce =
            self.get_next_destination_nonce(init_transfer.recipient.get_chain());
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
            fee: Self::denormalize_fee(&init_transfer.fee, decimals),
            sender: init_transfer.sender,
            msg: init_transfer.msg,
            destination_nonce,
            origin_transfer_id: None,
        };

        if let OmniAddress::Near(recipient) = transfer_message.recipient.clone() {
            self.process_fin_transfer_to_near(
                recipient,
                &predecessor_account_id,
                transfer_message,
                storage_deposit_actions,
            )
            .into()
        } else {
            self.process_fin_transfer_to_other_chain(predecessor_account_id, transfer_message);
            PromiseOrValue::Value(destination_nonce)
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L1136-1175)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn deploy_token(&mut self, #[serializer(borsh)] args: DeployTokenArgs) -> Promise {
        self.verify_proof(args.chain_kind, args.prover_args).then(
            Self::ext(env::current_account_id())
                .with_attached_deposit(NO_DEPOSIT)
                .with_static_gas(DEPLOY_TOKEN_CALLBACK_GAS)
                .deploy_token_callback(near_sdk::env::attached_deposit()),
        )
    }

    #[private]
    pub fn deploy_token_callback(
        &mut self,
        attached_deposit: NearToken,
        #[callback_result]
        #[serializer(borsh)]
        call_result: Result<ProverResult, PromiseError>,
    ) -> Promise {
        let Ok(ProverResult::LogMetadata(metadata)) = call_result else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str());
        };

        let chain = metadata.emitter_address.get_chain();
        require!(
            self.factories.get(&chain) == Some(metadata.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        self.deploy_token_internal(
            chain,
            &metadata.token_address,
            BasicMetadata {
                name: metadata.name,
                symbol: metadata.symbol,
                decimals: metadata.decimals,
            },
            attached_deposit,
        )
    }
```

**File:** near/omni-bridge/src/lib.rs (L1223-1301)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn bind_token(&mut self, #[serializer(borsh)] args: BindTokenArgs) -> Promise {
        self.verify_proof(args.chain_kind, args.prover_args)
            .then(
                Self::ext(env::current_account_id())
                    .with_attached_deposit(NO_DEPOSIT)
                    .with_static_gas(BIND_TOKEN_CALLBACK_GAS)
                    .bind_token_callback(near_sdk::env::attached_deposit()),
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_attached_deposit(env::attached_deposit())
                    .with_static_gas(BIND_TOKEN_REFUND_GAS)
                    .bind_token_refund(near_sdk::env::predecessor_account_id()),
            )
    }

    #[private]
    pub fn bind_token_callback(
        &mut self,
        attached_deposit: NearToken,
        #[callback_result]
        #[serializer(borsh)]
        call_result: Result<ProverResult, PromiseError>,
    ) -> NearToken {
        let Ok(ProverResult::DeployToken(deploy_token)) = call_result else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str());
        };

        require!(
            self.factories
                .get(&deploy_token.emitter_address.get_chain())
                == Some(deploy_token.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        let storage_usage = env::storage_usage();

        self.add_token(
            &deploy_token.token,
            &deploy_token.token_address,
            deploy_token.decimals,
            deploy_token.origin_decimals,
        );

        require!(
            self.locked_tokens
                .insert(
                    &(
                        deploy_token.token_address.get_chain(),
                        deploy_token.token.clone(),
                    ),
                    &0,
                )
                .is_none(),
            TokenLockError::TokenAlreadyLocked.as_ref()
        );

        let required_deposit = env::storage_byte_cost()
            .saturating_mul((env::storage_usage().saturating_sub(storage_usage)).into());

        require!(
            attached_deposit >= required_deposit,
            BridgeError::InsufficientStorageDeposit.as_ref()
        );

        env::log_str(
            &OmniBridgeEvent::BindTokenEvent {
                token_id: deploy_token.token,
                token_address: deploy_token.token_address,
                decimals: deploy_token.decimals,
                origin_decimals: deploy_token.origin_decimals,
            }
            .to_log_string(),
        );

        attached_deposit.saturating_sub(required_deposit)
    }
```
