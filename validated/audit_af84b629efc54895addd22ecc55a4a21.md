### Title
Unprotected `new()` Initializer Allows Any Caller to Seize `controller` and `bridge_id` Roles — (File: `contracts/nbtc/src/lib.rs`)

### Summary
The `nbtc` contract's `new()` initializer accepts arbitrary `controller` and `bridge_id` parameters with no check on who the caller is. Any account that calls `new()` before the legitimate deployer can install itself as both the `controller` and the `bridge_id`, gaining the exclusive right to mint, burn, and upgrade the nBTC token.

### Finding Description
`contracts/nbtc/src/lib.rs` `new()` only guards against re-initialization:

```rust
require!(!env::state_exists(), "Already initialized");
``` [1](#0-0) 

There is no check that `env::predecessor_account_id()` equals the contract account or any other trusted deployer. The function stores the caller-supplied `controller` and `bridge_id` verbatim:

```rust
let mut contract = Self {
    controller,
    bridge_id,
    ...
};
``` [2](#0-1) 

All privileged operations — `mint()`, `safe_mint()`, `burn()`, `set_controller()`, `upgrade_and_migrate()` — gate on exactly these two stored values:

```rust
fn assert_bridge(&self) {
    require!(self.bridge_id == env::predecessor_account_id(), "Not Allow");
}
fn assert_controller(&self) {
    require!(caller == self.controller, "ERR_MISSING_PERMISSION");
}
``` [3](#0-2) 

The deployment pattern used in the test harness (and expected in production) deploys the WASM in one transaction and calls `new()` in a separate transaction:

```rust
nbtc.deploy(&std::fs::read("../../res/nbtc.wasm")...)...
// separate call:
nbtc_contract.call("new").args_json(json!({...}))...
``` [4](#0-3) 

Between those two transactions there is an open window in which any NEAR account can call `new()` first.

### Impact Explanation
An attacker who wins the initialization race sets:
- `bridge_id` = their own contract account
- `controller` = their own account

Their contract then calls `mint()` on the nBTC token to mint an unbounded amount of nBTC to any recipient, with no BTC deposit ever made. This constitutes **unauthorized minting of nBTC**, a Critical impact under the allowed scope.

### Likelihood Explanation
NEAR transactions are publicly visible in the mempool. A bot watching for `DeployContract` actions on the known nBTC account ID can immediately submit a `new()` call with attacker-controlled parameters. The window exists every time the contract is (re-)deployed without atomically batching the `new()` call in the same transaction. The test harness confirms this two-step pattern is the intended deployment procedure.

### Recommendation
Restrict `new()` so it can only be called by the contract account itself (i.e., as part of a batch deploy transaction):

```rust
#[init]
pub fn new(controller: AccountId, bridge_id: AccountId, ...) -> Self {
    require!(
        env::predecessor_account_id() == env::current_account_id(),
        "Only the contract account may initialize"
    );
    require!(!env::state_exists(), "Already initialized");
    ...
}
```

This mirrors the `#[private]` pattern already used on `migrate()` and `migrate_from_poa()` in `contracts/nbtc/src/migrate.rs`. [5](#0-4) 

### Proof of Concept

1. Legitimate deployer submits transaction T1: `DeployContract` on account `nbtc.near` with the nBTC WASM.
2. Attacker observes T1 in the mempool and submits transaction T2 (higher gas priority): calls `nbtc.near::new({ controller: "attacker.near", bridge_id: "evil.attacker.near", ... })`.
3. T2 executes before the deployer's own `new()` call. State is now initialized with attacker-controlled roles.
4. Attacker deploys a minimal contract at `evil.attacker.near` that calls `nbtc.near::mint({ mint_account_id: "attacker.near", mint_amount: "21000000000000000", ... })`.
5. `assert_bridge()` passes because `self.bridge_id == "evil.attacker.near" == env::predecessor_account_id()`.
6. Arbitrary nBTC is minted to the attacker with no BTC backing. [6](#0-5)

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

**File:** contracts/nbtc/src/lib.rs (L68-84)
```rust
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

**File:** contracts/nbtc/src/lib.rs (L332-339)
```rust
    fn assert_bridge(&self) {
        require!(self.bridge_id == env::predecessor_account_id(), "Not Allow");
    }

    fn assert_controller(&self) {
        let caller = env::predecessor_account_id();
        require!(caller == self.controller, "ERR_MISSING_PERMISSION");
    }
```

**File:** contracts/satoshi-bridge/tests/setup/context.rs (L69-158)
```rust
            async {
                let nbtc = root
                    .create_subaccount("nbtc")
                    .initial_balance(NearToken::from_near(100))
                    .transact()
                    .await
                    .unwrap()
                    .unwrap();
                nbtc.deploy(&std::fs::read("../../res/nbtc.wasm").unwrap())
                    .await
                    .unwrap()
                    .unwrap()
            },
            async {
                worker
                    .dev_deploy(&std::fs::read("../../res/mock_chain_signatures.wasm").unwrap())
                    .await
                    .unwrap()
            },
            async {
                worker
                    .dev_deploy(&std::fs::read("../../res/mock_btc_light_client.wasm").unwrap())
                    .await
                    .unwrap()
            },
            async {
                let nbtc = root
                    .create_subaccount("dapp")
                    .initial_balance(NearToken::from_near(100))
                    .transact()
                    .await
                    .unwrap()
                    .unwrap();
                nbtc.deploy(&std::fs::read("../../res/mock_dapp.wasm").unwrap())
                    .await
                    .unwrap()
                    .unwrap()
            },
        );

        let (tx_listener, alice, bob, relayer, charlie) = tokio::join!(
            async {
                root.create_subaccount("tx_listener")
                    .initial_balance(NearToken::from_near(100))
                    .transact()
                    .await
                    .unwrap()
                    .unwrap()
            },
            async {
                root.create_subaccount("alice")
                    .initial_balance(NearToken::from_near(100))
                    .transact()
                    .await
                    .unwrap()
                    .unwrap()
            },
            async {
                root.create_subaccount("bob")
                    .initial_balance(NearToken::from_near(100))
                    .transact()
                    .await
                    .unwrap()
                    .unwrap()
            },
            async {
                root.create_subaccount("relayer")
                    .initial_balance(NearToken::from_near(100))
                    .transact()
                    .await
                    .unwrap()
                    .unwrap()
            },
            async { worker.dev_create_account().await.unwrap() },
        );

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

**File:** contracts/nbtc/src/migrate.rs (L31-35)
```rust
    #[private]
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        env::state_read().unwrap_or_else(|| env::panic_str("ERR_FAILED_TO_READ_STATE"))
    }
```
