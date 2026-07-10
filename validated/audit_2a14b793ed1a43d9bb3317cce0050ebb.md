### Title
Unprotected `new()` Initializer on nBTC Token Contract Allows Front-Running to Gain Unauthorized Minting Authority - (File: contracts/nbtc/src/lib.rs)

### Summary
The `nbtc` token contract's `new()` initializer accepts arbitrary `controller` and `bridge_id` parameters with no restriction on who may call it. Between the moment the WASM is deployed to the account and the moment the legitimate deployer calls `new()`, any unprivileged NEAR account can race in and call `new()` first, installing themselves as both `controller` and `bridge_id`. Because `bridge_id` is the sole gatekeeper for `mint()`, `safe_mint()`, and `burn()`, the attacker immediately gains the ability to mint unlimited nBTC to any account.

### Finding Description
`nbtc::Contract::new()` is a public `#[init]` function that takes caller-supplied `controller` and `bridge_id` values and writes them directly into contract state: [1](#0-0) 

The only guard is `require!(!env::state_exists(), "Already initialized")`, which prevents a *second* call but does nothing to restrict *who* makes the first call. [2](#0-1) 

The deployment pattern used in the test harness (and implied by the production setup) deploys the WASM and calls `new()` in **separate transactions**: [3](#0-2) 

This creates an observable window on-chain between the deploy transaction and the init transaction. Any account watching the mempool or block explorer can submit a `new()` call with attacker-controlled arguments before the legitimate deployer does.

Once the attacker's `new()` lands first, the contract state records:
- `controller` = attacker account
- `bridge_id` = attacker account [4](#0-3) 

All subsequent minting and burning is gated solely on `bridge_id == env::predecessor_account_id()`: [5](#0-4) 

The attacker, now acting as `bridge_id`, can call `mint()` directly: [6](#0-5) 

The same `assert_bridge()` guard protects `safe_mint()` and `burn()`, so the attacker controls the entire token supply. [7](#0-6) 

The `satoshi-bridge::Contract::new()` has the same structural issue — it grants DAO/super-admin roles to whoever calls it first — but the nBTC token contract is the more direct path to unauthorized minting. [8](#0-7) 

### Impact Explanation
An attacker who wins the initialization race becomes the sole authorized minter of nBTC. They can call `mint()` with arbitrary `mint_account_id` and `mint_amount`, creating nBTC tokens backed by no real BTC. This is **unauthorized minting** of the bridge's wrapped asset, directly matching the Critical impact category. The legitimate deployer's `new()` call will revert with "Already initialized", forcing a full redeployment — but by then the attacker's minted tokens already exist on-chain.

### Likelihood Explanation
NEAR transactions are publicly visible before finalization. Any account monitoring the chain for a `DeployContract` action targeting the nBTC account ID can immediately follow up with a `new()` call in the next block. No special privilege, leaked key, or operator access is required — only the ability to submit a standard NEAR transaction. The window exists whenever deploy and init are not batched atomically.

### Recommendation
Restrict `new()` to be callable only by the contract account itself (i.e., require `env::predecessor_account_id() == env::current_account_id()`), or — the standard NEAR pattern — deploy the WASM and call `new()` in a single **batch transaction** so both actions are atomic and the initialization window is eliminated. The `upgrade_and_migrate` function already demonstrates the correct atomic pattern: [9](#0-8) 

Apply the same batch-deploy approach to the initial deployment.

### Proof of Concept
1. Legitimate deployer submits `DeployContract` action to the `nbtc` account. The WASM is now live but `new()` has not been called.
2. Attacker observes the deploy transaction on-chain and immediately submits:
   ```
   nbtc.call("new", {
     controller: "attacker.near",
     bridge_id: "attacker.near",
     name: "nBTC", symbol: "nBTC", icon: null, decimals: 8
   })
   ```
3. Attacker's `new()` lands first. `env::state_exists()` is now `true`; `bridge_id = "attacker.near"`.
4. Legitimate deployer's `new()` reverts: `"Already initialized"`.
5. Attacker calls `mint()` from `attacker.near`:
   ```
   nbtc.call("mint", {
     mint_account_id: "attacker.near",
     mint_amount: "1000000000000",   // 10,000 BTC in satoshis
     protocol_fee: "0",
     relayer_account_id: "attacker.near",
     relayer_fee: "0",
     post_actions: null
   })
   ```
6. `assert_bridge()` passes because `bridge_id == predecessor_account_id == "attacker.near"`. [10](#0-9) 
7. `mint_inner()` deposits the full amount to the attacker's account with no BTC backing. [11](#0-10)

### Citations

**File:** contracts/nbtc/src/lib.rs (L58-91)
```rust
    #[init]
    pub fn new(
        controller: AccountId,
        bridge_id: AccountId,
        name: String,
        symbol: String,
        icon: Option<String>,
        decimals: u8,
    ) -> Self {
        require!(!env::state_exists(), "Already initialized");
        let mut contract = Self {
            controller,
            bridge_id,
            token: FungibleToken::new(StorageKey::FungibleToken),
            metadata: LazyOption::new(
                StorageKey::Metadata,
                Some(&FungibleTokenMetadata {
                    spec: FT_METADATA_SPEC.to_string(),
                    name,
                    symbol,
                    icon,
                    reference: None,
                    reference_hash: None,
                    decimals,
                }),
            ),
        };

        contract
            .token
            .internal_register_account(&contract.bridge_id);

        contract
    }
```

**File:** contracts/nbtc/src/lib.rs (L107-107)
```rust
        self.assert_bridge();
```

**File:** contracts/nbtc/src/lib.rs (L126-148)
```rust
    pub fn mint(
        &mut self,
        mint_account_id: AccountId,
        mint_amount: U128,
        protocol_fee: U128,
        relayer_account_id: AccountId,
        relayer_fee: U128,
        post_actions: Option<Vec<PostAction>>,
    ) {
        self.assert_bridge();
        self.mint_inner(&mint_account_id, mint_amount);
        if protocol_fee.0 > 0 {
            self.mint_inner(&self.bridge_id.clone(), protocol_fee);
        }
        if relayer_fee.0 > 0 {
            self.mint_inner(&relayer_account_id, relayer_fee);
        }
        if let Some(post_actions) = post_actions {
            Self::ext(env::current_account_id())
                .handle_post_actions(mint_account_id, post_actions)
                .detach();
        }
    }
```

**File:** contracts/nbtc/src/lib.rs (L332-334)
```rust
    fn assert_bridge(&self) {
        require!(self.bridge_id == env::predecessor_account_id(), "Not Allow");
    }
```

**File:** contracts/nbtc/src/lib.rs (L341-351)
```rust
    fn mint_inner(&mut self, account_id: &AccountId, amount: U128) {
        if self.token.accounts.get(account_id).is_none() {
            self.token.internal_register_account(account_id);
        }
        self.token.internal_deposit(account_id, amount.into());
        near_contract_standards::fungible_token::events::FtMint {
            owner_id: account_id,
            amount,
            memo: None,
        }
        .emit();
```

**File:** contracts/satoshi-bridge/tests/setup/context.rs (L145-158)
```rust
        nbtc_contract
            .call("new")
            .args_json(json!({
                "controller": root.id(),
                "bridge_id": bridge_contract.id(),
                "name": "Near BTC".to_string(),
                "symbol": "NBTC".to_string(),
                "icon": Some(DATA_IMAGE_SVG_NEAR_ICON.to_string()),
                "decimals": 8,
            }))
            .transact()
            .await
            .unwrap()
            .unwrap();
```

**File:** contracts/satoshi-bridge/src/lib.rs (L182-230)
```rust
    #[init]
    pub fn new(config: Config) -> Self {
        config.assert_valid();
        require!(
            config.chain_signatures_root_public_key.is_none(),
            "Init chain_signatures_root_public_key must be None"
        );
        require!(
            config.change_address.is_none(),
            "Init change_address must be None"
        );
        let mut contract = Self {
            data: VersionedContractData::Current(ContractData {
                config: LazyOption::new(StorageKey::Config, Some(config)),
                accounts: IterableMap::new(StorageKey::Accounts),
                utxos: IterableMap::new(StorageKey::UTXOs),
                unavailable_utxos: IterableMap::new(StorageKey::UnavailableUTXOs),
                verified_deposit_utxo: LookupSet::new(StorageKey::VerifiedDepositUtxos),
                btc_pending_infos: IterableMap::new(StorageKey::BTCPendingInfos),
                rbf_txs: IterableMap::new(StorageKey::RbfTxs),
                relayer_white_list: IterableSet::new(StorageKey::RelayerWhiteList),
                extra_msg_relayer_white_list: IterableSet::new(
                    StorageKey::ExtraMsgRelayerWhiteList,
                ),
                post_action_receiver_id_white_list: IterableSet::new(
                    StorageKey::PostActionReceiverIdWhiteListWhiteList,
                ),
                post_action_msg_templates: IterableMap::new(StorageKey::PostActionMsgTemplates),
                pending_tx_limits: IterableMap::new(StorageKey::PendingTxLimits),
                lost_found: IterableMap::new(StorageKey::LostFound),
                refund_requests: IterableMap::new(StorageKey::RefundRequests),
                acc_collected_protocol_fee: 0,
                cur_available_protocol_fee: 0,
                acc_claimed_protocol_fee: 0,
                cur_reserved_protocol_fee: 0,
                acc_protocol_fee_for_gas: 0,
            }),
        };
        contract.acl_init_super_admin(env::predecessor_account_id());
        contract.acl_grant_role(Role::DAO.into(), env::predecessor_account_id());
        contract.acl_grant_role(Role::PauseManager.into(), env::predecessor_account_id());
        contract.acl_grant_role(Role::UnpauseManager.into(), env::predecessor_account_id());

        contract.internal_set_account(
            &env::predecessor_account_id(),
            Account::new(&env::predecessor_account_id()),
        );
        contract
    }
```

**File:** contracts/nbtc/src/migrate.rs (L78-99)
```rust
    pub fn upgrade_and_migrate(&self) {
        self.assert_controller();

        // Receive the code directly from the input to avoid the
        // GAS overhead of deserializing parameters
        let code = env::input().unwrap_or_else(|| env::panic_str("ERR_NO_INPUT"));
        // Deploy the contract code.
        let promise_id = env::promise_batch_create(&env::current_account_id());
        env::promise_batch_action_deploy_contract(promise_id, &code);
        // Call promise to migrate the state.
        // Batched together to fail upgrade if migration fails.
        env::promise_batch_action_function_call(
            promise_id,
            "migrate",
            b"",
            NO_DEPOSIT,
            env::prepaid_gas()
                .saturating_sub(env::used_gas())
                .saturating_sub(OUTER_UPGRADE_GAS),
        );
        env::promise_return(promise_id);
    }
```
