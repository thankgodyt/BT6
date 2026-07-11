### Title
Unguarded `new` Initializer Allows Attacker to Seize Controller and Bridge Roles Before Deployer — (`contracts/nbtc/src/lib.rs`)

---

### Summary
The `nbtc` token contract's `new` initializer accepts arbitrary `controller` and `bridge_id` parameters from any caller and performs no check that the caller is the deployer or any trusted address. If the deployer deploys the contract code in one transaction and calls `new` in a separate transaction, an attacker who observes the deployment can call `new` first, set themselves as both `controller` and `bridge_id`, and subsequently call the unrestricted `mint` function to mint arbitrary nBTC.

---

### Finding Description

`nbtc::new` is the sole initialization entry point for the nBTC token contract: [1](#0-0) 

The only guard present is:

```rust
require!(!env::state_exists(), "Already initialized");
```

There is no check that `env::predecessor_account_id()` equals the contract's own account, the deployer, or any other trusted address. The `controller` and `bridge_id` fields are accepted verbatim from the caller's arguments. [2](#0-1) 

The `mint` function, which creates nBTC tokens, enforces only:

```rust
fn assert_bridge(&self) {
    require!(self.bridge_id == env::predecessor_account_id(), "Not Allow");
}
``` [3](#0-2) 

If an attacker initializes the contract with `bridge_id = attacker_account`, the `assert_bridge` check passes for any call the attacker makes directly, enabling unrestricted minting. [4](#0-3) 

The same structural problem exists in `satoshi-bridge::new`, where the caller is unconditionally granted `acl_init_super_admin`, `Role::DAO`, `Role::PauseManager`, and `Role::UnpauseManager`: [5](#0-4) 

---

### Impact Explanation

**Critical.** An attacker who front-runs `nbtc::new` can:

1. Set `bridge_id` to their own NEAR account.
2. Call `mint(attacker_account, U128(MAX), ...)` directly — `assert_bridge` passes because `bridge_id == predecessor`.
3. Mint an unbounded quantity of nBTC with no corresponding BTC deposit.

This constitutes **unauthorized minting of nBTC**, directly violating the bridge's core invariant that every nBTC token is backed by a real BTC deposit.

Additionally, front-running `satoshi-bridge::new` grants the attacker full DAO/super-admin control over the bridge, enabling manipulation of the light-client address, chain-signatures contract, fee parameters, and relayer whitelist — a complete bypass of all authorization controls.

---

### Likelihood Explanation

**Medium.** In NEAR Protocol, contract deployment (`DeployContract` action) and initialization (`FunctionCall` to `new`) are separate actions that can be batched in one transaction but are not required to be. If the deployer uses two separate transactions (common with CLI tooling or scripted deployments), there is an observable window between code deployment and initialization. An attacker monitoring the chain for `DeployContract` actions targeting these contract accounts can immediately submit a `new` call with malicious parameters. NEAR does not have a traditional mempool, making classic front-running harder than on EVM chains, but the window exists whenever deployment and initialization are not atomic.

---

### Recommendation

Verify the caller is the contract's own account (i.e., the deployer) inside `new`. The NEAR SDK pattern is:

```rust
#[init]
pub fn new(controller: AccountId, bridge_id: AccountId, ...) -> Self {
    require!(
        env::predecessor_account_id() == env::current_account_id(),
        "Only the contract account may initialize"
    );
    require!(!env::state_exists(), "Already initialized");
    // ...
}
```

Alternatively, batch the `DeployContract` and `FunctionCall` actions into a single transaction at the protocol level so initialization is atomic with deployment, and document this as a required deployment invariant.

Apply the same fix to `satoshi-bridge::new`. [6](#0-5) 

---

### Proof of Concept

1. Deployer submits TX-1: `DeployContract` action on `nbtc.near` — contract code is live, state does not yet exist.
2. Attacker observes TX-1 on-chain and immediately submits TX-2: `FunctionCall { method: "new", args: { controller: "attacker.near", bridge_id: "attacker.near", ... } }`.
3. TX-2 executes before the deployer's initialization TX-3. `env::state_exists()` is `false`, so the `require!` passes. State is written with `controller = attacker.near`, `bridge_id = attacker.near`.
4. Deployer's TX-3 (`new`) panics: `"Already initialized"`. Deployer may not immediately notice the contract is under attacker control.
5. Attacker calls `mint(attacker.near, U128(1_000_000_000_000), U128(0), attacker.near, U128(0), None)`. `assert_bridge` passes (`bridge_id == predecessor == attacker.near`). nBTC tokens are minted with no BTC backing. [7](#0-6)

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
