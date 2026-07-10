### Title
Initialization Frontrunning Allows Attacker to Seize `bridge_id` and Mint Unlimited nBTC - (File: contracts/nbtc/src/lib.rs)

### Summary
The `nbtc` token contract's `new()` constructor accepts `controller` and `bridge_id` as arbitrary caller-supplied parameters with no binding to the deployer's identity. If the deployment transaction and the initialization call are submitted as separate NEAR transactions, any unprivileged account can race to call `new()` first, install themselves as both `controller` and `bridge_id`, and subsequently call `mint()` without restriction to create unlimited nBTC.

### Finding Description
The `nbtc` contract's `#[init]` function accepts `controller` and `bridge_id` as free parameters and writes them directly into contract state:

```rust
pub fn new(
    controller: AccountId,
    bridge_id: AccountId,
    ...
) -> Self {
    require!(!env::state_exists(), "Already initialized");
    let mut contract = Self {
        controller,
        bridge_id,
        ...
    };
``` [1](#0-0) 

Neither field is derived from `env::predecessor_account_id()` nor from any deployer-controlled commitment. The only guard is `require!(!env::state_exists(), ...)`, which only prevents a second initialization — it does not prevent a racing first initialization by an attacker.

The `mint()` function, which can create arbitrary amounts of nBTC, is gated solely by:

```rust
fn assert_bridge(&self) {
    require!(self.bridge_id == env::predecessor_account_id(), "Not Allow");
}
``` [2](#0-1) 

If an attacker controls `bridge_id`, they satisfy this check unconditionally and can call `mint()` at will:

```rust
pub fn mint(
    &mut self,
    mint_account_id: AccountId,
    mint_amount: U128,
    ...
) {
    self.assert_bridge();
    self.mint_inner(&mint_account_id, mint_amount);
``` [3](#0-2) 

The same `assert_bridge()` guard also protects `burn()` and `safe_mint()`, meaning the attacker gains full control over the token supply. [4](#0-3) 

### Impact Explanation
An attacker who wins the initialization race becomes both `controller` and `bridge_id`. From `bridge_id` they can call `mint()` to create an unbounded quantity of nBTC and distribute it to any registered account. This constitutes **unauthorized minting of nBTC** — the bridged representation of real Bitcoin — directly matching the Critical impact class. The attacker can also call `set_controller()` (gated by `assert_controller()`) to permanently lock out the legitimate deployer from any recovery path. [5](#0-4) 

### Likelihood Explanation
NEAR deployments commonly separate the `DeployContract` action from the subsequent `FunctionCall` to `new()` into distinct transactions, especially when using CLI tooling or scripts. During the block interval between those two transactions the contract exists on-chain with no state, and any NEAR account can submit a `new()` call. The attacker needs no special access, no leaked key, and no privileged position — only the ability to observe the deployment transaction in the mempool or on-chain and submit a competing transaction before the legitimate init lands.

### Recommendation
Bind initialization to the deployer's identity by requiring that `controller` and `bridge_id` match `env::predecessor_account_id()`, or by hardcoding them from `env::predecessor_account_id()` inside `new()`. Alternatively, always deploy and initialize in a single atomic NEAR batch transaction (combining `DeployContract` and `FunctionCall` actions), which eliminates the frontrunning window entirely. The same pattern should be applied to the `satoshi-bridge` contract's `new()` constructor, which similarly grants DAO/super-admin roles to whoever calls it first. [6](#0-5) 

### Proof of Concept
1. Legitimate deployer submits `DeployContract` for the `nbtc` account in transaction T1.
2. Attacker observes T1 and immediately submits a `FunctionCall` to `nbtc::new(attacker.near, attacker.near, "nBTC", "nBTC", None, 8)` in transaction T2, which lands before the deployer's own init call T3.
3. T3 fails with `"Already initialized"` — the deployer cannot recover without redeploying to a new account.
4. Attacker calls `nbtc::mint(victim.near, U128(100_000_000_000), U128(0), attacker.near, U128(0), None)` from `attacker.near`.
5. `assert_bridge()` passes because `self.bridge_id == attacker.near == env::predecessor_account_id()`.
6. `mint_inner` deposits 100 000 000 000 satoshi-equivalent nBTC to `victim.near` (or any account), with no corresponding BTC locked on-chain. [7](#0-6)

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

**File:** contracts/nbtc/src/lib.rs (L93-98)
```rust
    #[payable]
    pub fn set_controller(&mut self, controller: AccountId) {
        assert_one_yocto();
        self.assert_controller();
        self.controller = controller;
    }
```

**File:** contracts/nbtc/src/lib.rs (L100-124)
```rust
    #[payable]
    pub fn safe_mint(
        &mut self,
        account_id: AccountId,
        amount: U128,
        msg: Option<String>,
    ) -> PromiseOrValue<U128> {
        self.assert_bridge();
        require!(
            account_id != self.bridge_id,
            "safe_mint: account_id must not be the bridge"
        );
        self.token.internal_deposit(&self.bridge_id, amount.into());

        if self.token.accounts.get(&account_id).is_none() {
            return PromiseOrValue::Value(U128(0));
        }

        if let Some(msg) = msg {
            self.ft_transfer_call(account_id, amount, None, msg)
        } else {
            self.ft_transfer(account_id, amount, None);
            PromiseOrValue::Value(amount)
        }
    }
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

**File:** contracts/nbtc/src/lib.rs (L150-177)
```rust
    pub fn burn(
        &mut self,
        burn_account_id: AccountId,
        burn_amount: U128,
        relayer_account_id: AccountId,
        relayer_fee: U128,
    ) {
        self.assert_bridge();
        self.token
            .internal_withdraw(&self.bridge_id, burn_amount.into());
        if relayer_fee.0 > 0 {
            if self.token.accounts.get(&relayer_account_id).is_none() {
                self.token.internal_register_account(&relayer_account_id);
            }
            self.token.internal_transfer(
                &self.bridge_id,
                &relayer_account_id,
                relayer_fee.into(),
                None,
            );
        }
        near_contract_standards::fungible_token::events::FtBurn {
            owner_id: &burn_account_id,
            amount: burn_amount,
            memo: None,
        }
        .emit();
    }
```

**File:** contracts/nbtc/src/lib.rs (L332-334)
```rust
    fn assert_bridge(&self) {
        require!(self.bridge_id == env::predecessor_account_id(), "Not Allow");
    }
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
