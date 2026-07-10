### Title
Unprotected `new()` Initializers Allow Front-Running to Seize Full Bridge and Token Control — (File: `contracts/nbtc/src/lib.rs`, `contracts/satoshi-bridge/src/lib.rs`)

---

### Summary
Both the `nbtc` token contract and the `satoshi-bridge` contract expose public `new()` initializers that accept arbitrary caller-supplied parameters and grant privileged roles to `env::predecessor_account_id()`. Neither function restricts who may call it. If the deployment script deploys the contract bytecode in one transaction and calls `new()` in a subsequent transaction, any unprivileged NEAR account can race to call `new()` first, seizing full ownership of the token contract (enabling unauthorized minting) and full DAO/admin control of the bridge.

---

### Finding Description

**Root cause — `nbtc` contract (`contracts/nbtc/src/lib.rs`):**

The `new()` initializer accepts `controller` and `bridge_id` as caller-supplied parameters and has no check that the caller is the deployer or any specific account. [1](#0-0) 

The only guard is `require!(!env::state_exists(), "Already initialized")`, which prevents double-initialization but does nothing to prevent a racing attacker from being the *first* caller. [2](#0-1) 

The `bridge_id` field is the sole authorization gate for `mint()` and `burn()`: [3](#0-2) 

If an attacker calls `new(attacker_acct, attacker_acct, ...)` first, they set `controller = attacker_acct` and `bridge_id = attacker_acct`. The attacker's account is then registered in the token ledger: [4](#0-3) 

From that point, the attacker can call `mint()` freely to issue arbitrary nBTC to any account.

---

**Root cause — `satoshi-bridge` contract (`contracts/satoshi-bridge/src/lib.rs`):**

The `new()` initializer is decorated with `#[init]` (which only prevents double-initialization) and grants super-admin, DAO, PauseManager, and UnpauseManager roles unconditionally to `env::predecessor_account_id()`: [5](#0-4) 

Specifically, the role grants: [6](#0-5) 

An attacker who front-runs this call with a syntactically valid `Config` (setting `nbtc_account_id` to their own token contract, `btc_light_client_account_id` to their own mock, etc.) becomes the DAO and super-admin of the bridge, with full authority over all privileged operations.

---

### Impact Explanation

**`nbtc` front-run:** The attacker controls `bridge_id`, which is the only authorization check in `mint()`. They can mint unlimited nBTC to any account. This is **unauthorized minting of nBTC** — Critical.

**`satoshi-bridge` front-run:** The attacker becomes DAO/super-admin. They can grant/revoke all roles, set the `chain_signatures_root_public_key` and `change_address`, whitelist relayers, and control all bridge funds. This is a **complete bypass of bridge authorization controls** — Critical.

---

### Likelihood Explanation

NEAR contract deployment is a two-step process: deploy bytecode, then call the initializer. If these are separate transactions (as is common in deployment scripts), the window between them is publicly observable on-chain. Any NEAR account can monitor the mempool/chain for a newly deployed but uninitialized contract and submit a `new()` call before the legitimate deployer. The attack requires no special knowledge, no funds beyond gas, and no privileged access.

---

### Recommendation

Deploy and initialize in a single atomic batch transaction using NEAR's `DeployContract` + `FunctionCall` batch action. This eliminates the window between deployment and initialization entirely, as both actions execute atomically in the same block.

Alternatively, add a deployer check inside `new()` by requiring `env::predecessor_account_id() == env::current_account_id()` or by encoding the expected deployer account at compile time.

---

### Proof of Concept

1. Legitimate deployer broadcasts a `DeployContract` transaction for `nbtc` (bytecode only, no init call yet).
2. Attacker observes the new account on-chain with no state.
3. Attacker calls:
   ```
   nbtc.new(
     controller = "attacker.near",
     bridge_id  = "attacker.near",
     name = "nBTC", symbol = "nBTC", icon = None, decimals = 8
   )
   ```
4. `env::state_exists()` is false → the call succeeds. `controller` and `bridge_id` are now `attacker.near`.
5. Legitimate deployer's subsequent `new()` call fails with `"Already initialized"`.
6. Attacker calls `nbtc.mint(mint_account_id = "victim.near", mint_amount = 100_000_000_000, ...)` — `assert_bridge()` passes because `bridge_id == env::predecessor_account_id() == attacker.near`.
7. Unlimited nBTC is minted to any target account.

The same race applies to `satoshi-bridge.new(config)`, after which the attacker holds all DAO/admin roles. [7](#0-6) [5](#0-4)

### Citations

**File:** contracts/nbtc/src/lib.rs (L58-67)
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
```

**File:** contracts/nbtc/src/lib.rs (L87-89)
```rust
            .token
            .internal_register_account(&contract.bridge_id);

```

**File:** contracts/nbtc/src/lib.rs (L126-135)
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
