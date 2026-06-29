Audit Report

## Title
Pause Bypass via Async `fin_transfer_callback` Allows Token Minting/Unlocking When Contract Is Paused — (`near/omni-bridge/src/lib.rs`)

## Summary

`fin_transfer` enforces a pause guard via `#[pause(except(roles(Role::DAO)))]`, but its async continuation `fin_transfer_callback` carries only `#[private]` with no pause check. Because NEAR promise callbacks execute in a subsequent receipt — potentially in a different block — the contract can be paused between the two steps, and `fin_transfer_callback` will still complete the transfer, minting or unlocking bridged tokens in violation of the intended pause protection. The same structural gap exists in `deploy_token_callback` and `bind_token_callback`.

## Finding Description

`fin_transfer` at L670–696 is decorated with `#[pause(except(roles(Role::DAO)))]` and `#[trusted_relayer]`, preventing non-DAO callers from initiating new inbound finalizations while the contract is paused. [1](#0-0) 

It schedules a cross-contract proof-verification call and chains `fin_transfer_callback` as the continuation. `fin_transfer_callback` at L698–746 is marked only `#[private]` — it has **no pause check**: [2](#0-1) 

Inside the callback, `process_fin_transfer_to_near` (L1868+) is called for NEAR-bound transfers, which calls `add_fin_transfer` (inserting into `finalised_transfers` for replay protection) and then mints or transfers tokens to the recipient. For transfers routed to other chains, `process_fin_transfer_to_other_chain` (L1980+) is called, which records a new outbound transfer message and adjusts locked token balances. [3](#0-2) 

The `add_fin_transfer` function at L2226–2234 only prevents replay of the same transfer ID — it does not check the pause state: [4](#0-3) 

The same pattern exists for `deploy_token_callback` (L1148+) and `bind_token_callback` (L1241+), both called from paused entry points but themselves carrying no pause check. [5](#0-4) 

## Impact Explanation

This is a **pause bypass** — explicitly listed as a Critical allowed impact. A `PauseManager` pausing the contract in response to a detected exploit cannot retroactively cancel already-scheduled callbacks. Any `fin_transfer` call submitted before the pause transaction is confirmed will produce a `fin_transfer_callback` receipt that executes regardless of the pause state, causing the bridge to mint or release bridged tokens to the recipient during a security incident window when the protocol is supposed to be fully halted. This constitutes unauthorized minting or unlocking of bridged funds during an active pause. [6](#0-5) 

## Likelihood Explanation

NEAR promise callbacks execute in a subsequent receipt, which may land in a different block from the originating call. A `PauseManager` pausing the contract in response to a detected exploit cannot retroactively cancel already-scheduled callbacks. Any `fin_transfer` call submitted before the pause transaction is confirmed will produce a callback that bypasses the pause. This requires no special attacker capability beyond submitting a normal bridge finalization as a trusted relayer — a role explicitly included in the valid trigger surface ("relayer flows") per the program rules. The trusted relayer role is an operational role (staked and approved), not a governance/admin role, and the scenario does not require the relayer to act maliciously; it is a structural race condition inherent to NEAR's async execution model. [7](#0-6) 

## Recommendation

Add a pause guard at the start of `fin_transfer_callback`. Using the `near-plugins` `Pausable` trait already imported by the contract, check `self.is_paused()` (or apply the `#[pause]` macro) before processing the prover result. If the contract is paused, the callback should refund any attached deposit and return without minting or recording any state change. Apply the same fix to `deploy_token_callback` and `bind_token_callback`. [8](#0-7) 

## Proof of Concept

1. The bridge is operating normally. A trusted relayer submits `fin_transfer` for a large inbound transfer (e.g., 1,000,000 USDC from Ethereum to NEAR). The call passes the pause check and schedules `verify_proof` → `fin_transfer_callback`.
2. In the same or next block, a `PauseManager` detects an exploit and calls `pa_pause` to halt the contract.
3. In the following block, the NEAR runtime delivers the `fin_transfer_callback` receipt. Because `fin_transfer_callback` has no pause check, it reads the prover result, validates the factory, and calls `process_fin_transfer_to_near`, which mints 1,000,000 USDC to the recipient.
4. The pause intended to freeze all bridge operations has been bypassed; tokens have been minted during the incident window.

**Reproducible test plan:** In a near-workspaces integration test, (a) set up a trusted relayer and submit `fin_transfer` with a valid mock prover result, (b) before the callback receipt is processed, call `pa_pause` from a `PauseManager` account, (c) allow the callback to execute and assert that `is_transfer_finalised` returns `true` and the recipient's token balance increased — demonstrating that the pause had no effect on the in-flight callback. [9](#0-8)

### Citations

**File:** near/omni-bridge/src/lib.rs (L4-7)
```rust
use near_plugins::{
    access_control, access_control_any, pause, AccessControlRole, AccessControllable, Pausable,
    Upgradable,
};
```

**File:** near/omni-bridge/src/lib.rs (L209-212)
```rust
#[near(contract_state)]
#[derive(Pausable, Upgradable, PanicOnDefault)]
#[access_control(role_type(Role))]
#[pausable(manager_roles(Role::PauseManager))]
```

**File:** near/omni-bridge/src/lib.rs (L245-249)
```rust
#[trusted_relayer(
    bypass_roles(Role::DAO, Role::UnrestrictedRelayer),
    manager_roles(Role::DAO, Role::RelayerManager),
    config_roles(Role::DAO)
)]
```

**File:** near/omni-bridge/src/lib.rs (L670-696)
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
```

**File:** near/omni-bridge/src/lib.rs (L698-746)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L1148-1175)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L1980-2005)
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
