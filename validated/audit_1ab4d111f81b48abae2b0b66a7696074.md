### Title
Unprotected `new()` Initializer Allows Anyone to Seize Full Admin Control of the Bridge — (`File: near/omni-bridge/src/lib.rs`)

### Summary
The `Contract::new()` initializer in the NEAR `omni-bridge` contract has no caller restriction. Any account that calls it before the legitimate deployer becomes the permanent super-admin and DAO role holder, gaining unrestricted control over every privileged bridge operation.

### Finding Description
`Contract::new()` is annotated with `#[init]` (which prevents re-initialization once state exists) but carries **no access-control guard** on who may perform that first call. [1](#0-0) 

The function unconditionally promotes `env::predecessor_account_id()` to super-admin and DAO:

```rust
contract.acl_init_super_admin(near_sdk::env::predecessor_account_id());
contract.acl_grant_role(Role::DAO.into(), near_sdk::env::predecessor_account_id());
``` [2](#0-1) 

The same pattern exists in `token-deployer`: [3](#0-2) 

The inconsistency is visible by comparing with contracts that **do** restrict initialization:

- `omni-token/src/lib.rs` explicitly requires `predecessor_account_id() == deployer_account` (the parent account): [4](#0-3) 

- All three prover contracts (`mpc-omni-prover`, `evm-prover`, `wormhole-omni-prover-proxy`) combine `#[init]` with `#[private]`, restricting the call to the contract itself: [5](#0-4) [6](#0-5) [7](#0-6) 

The `omni-bridge` and `token-deployer` contracts are the only production contracts that omit this protection.

### Impact Explanation
Whoever calls `new()` first is granted:
- `acl_super_admin` — the root of the entire access-control hierarchy
- `Role::DAO` — controls factory registration, prover registration, token deployer accounts, MPC signer, WNEAR account, contract upgrades, and all pause/unpause operations

An attacker holding these roles can:
1. Register a malicious factory address, causing the bridge to accept forged cross-chain events.
2. Register a malicious prover, bypassing all proof verification and enabling unauthorized minting or fund release.
3. Upgrade the contract to an arbitrary implementation, draining all locked funds.
4. Permanently pause the bridge, freezing all user funds.

This satisfies the **Critical** impact tier: authorization bypass and admin-equivalent action execution over the entire bridge.

### Likelihood Explanation
In NEAR, contract deployment (`DeployContract` action) and initialization (`new()` call) are separate actions. If they are submitted as a single batch transaction they are atomic; if submitted as two separate transactions there is an observable window between them. An attacker monitoring the NEAR RPC for `DeployContract` receipts targeting the bridge account can submit a competing `new()` call in that window. The root cause is the **absent access-control check**, not merely the timing — the fix is an explicit caller guard, not just deployment atomicity.

### Recommendation
Add a caller restriction to `Contract::new()` and `TokenDeployer::new()`, mirroring the pattern already used in `omni-token`:

```rust
#[init]
pub fn new(mpc_signer: AccountId, wnear_account_id: AccountId) -> Self {
    // Restrict to the account that deployed this contract
    let deployer = env::current_account_id()
        .get_parent_account_id()
        .expect("No parent account");
    require!(
        env::predecessor_account_id() == deployer,
        "Only the deployer account can initialize this contract"
    );
    // ... rest of init
}
```

Alternatively, mark `new()` as `#[private]` and ensure deployment and initialization are always submitted as a single atomic batch action, as is done for all prover contracts.

### Proof of Concept
1. Monitor the NEAR RPC for a `DeployContract` action targeting the `omni-bridge` account.
2. Before the deployer's `new()` transaction is included, submit:
   ```
   near call <omni-bridge-account> new \
     '{"mpc_signer":"attacker.near","wnear_account_id":"wrap.near"}' \
     --accountId attacker.near
   ```
3. `attacker.near` is now `acl_super_admin` and holds `Role::DAO`.
4. Attacker calls `set_factory`, `add_prover`, or `upgrade` to redirect bridge operations to attacker-controlled contracts, enabling theft of all bridged assets.

### Citations

**File:** near/omni-bridge/src/lib.rs (L285-314)
```rust
    #[init]
    pub fn new(mpc_signer: AccountId, wnear_account_id: AccountId) -> Self {
        let mut contract = Self {
            factories: LookupMap::new(StorageKey::Factories),
            pending_transfers: LookupMap::new(StorageKey::PendingTransfers),
            finalised_transfers: LookupSet::new(StorageKey::FinalisedTransfers),
            finalised_utxo_transfers: LookupSet::new(StorageKey::FinalisedUtxoTransfers),
            fast_transfers: LookupMap::new(StorageKey::FastTransfers),
            token_id_to_address: LookupMap::new(StorageKey::TokenIdToAddress),
            token_address_to_id: LookupMap::new(StorageKey::TokenAddressToId),
            token_decimals: LookupMap::new(StorageKey::TokenDecimals),
            deployed_tokens: LookupSet::new(StorageKey::DeployedTokens),
            deployed_tokens_v2: LookupMap::new(StorageKey::DeployedTokensV2),
            token_deployer_accounts: LookupMap::new(StorageKey::TokenDeployerAccounts),
            mpc_signer,
            current_origin_nonce: 0,
            destination_nonces: LookupMap::new(StorageKey::DestinationNonces),
            accounts_balances: LookupMap::new(StorageKey::AccountsBalances),
            wnear_account_id,
            provers: UnorderedMap::new(StorageKey::RegisteredProvers),
            init_transfer_promises: LookupMap::new(StorageKey::InitTransferPromises),
            utxo_chain_connectors: HashMap::new(),
            migrated_tokens: LookupMap::new(StorageKey::MigratedTokens),
            locked_tokens: LookupMap::new(StorageKey::LockedTokens),
        };

        contract.acl_init_super_admin(near_sdk::env::predecessor_account_id());
        contract.acl_grant_role(Role::DAO.into(), near_sdk::env::predecessor_account_id());
        contract
    }
```

**File:** near/token-deployer/src/lib.rs (L45-56)
```rust
    #[init]
    pub fn new(controller: AccountId, dao: AccountId, global_code_hash: Base58CryptoHash) -> Self {
        let mut contract = Self {
            global_code_hash: global_code_hash.into(),
        };

        contract.acl_init_super_admin(near_sdk::env::predecessor_account_id());
        contract.acl_grant_role(Role::DAO.into(), dao.clone());
        contract.acl_grant_role(Role::Controller.into(), controller);
        contract.acl_transfer_super_admin(dao);
        contract
    }
```

**File:** near/omni-token/src/lib.rs (L56-60)
```rust

        require!(
            env::predecessor_account_id().as_str() == deployer_account,
            "Only the deployer account can init this contract"
        );
```

**File:** near/omni-prover/mpc-omni-prover/src/lib.rs (L52-55)
```rust
    #[init]
    #[private]
    #[must_use]
    pub fn init(mpc_contract_id: AccountId) -> Self {
```

**File:** near/omni-prover/evm-prover/src/lib.rs (L39-43)
```rust
    #[init]
    #[private]
    #[must_use]
    pub fn init(light_client: AccountId, chain_kind: ChainKind) -> Self {
        Self {
```

**File:** near/omni-prover/wormhole-omni-prover-proxy/src/lib.rs (L28-32)
```rust
    #[init]
    #[private]
    #[must_use]
    pub const fn init(prover_account: AccountId) -> Self {
        Self { prover_account }
```
