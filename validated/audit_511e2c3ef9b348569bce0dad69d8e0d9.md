### Title
Uninitialized nBTC Token Contract Allows Attacker to Seize Controller Role and Gain Unauthorized Minting Capability — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

The nBTC token contract's `new()` initialization function is publicly callable by any NEAR account before the contract state exists. The `#[init]` attribute only guards against re-initialization (`!env::state_exists()`), but places no restriction on *who* may call it. When a new nBTC contract is deployed in a separate transaction from its initialization — the pattern shown throughout this codebase — an attacker can front-run the `new()` call, installing themselves as `controller` while setting `bridge_id` to the legitimate bridge contract. As `controller`, the attacker can invoke `attach_full_access_key()` to gain a full-access key on the token contract, then deploy arbitrary malicious code to mint unbacked nBTC.

---

### Finding Description

The nBTC contract derives `PanicOnDefault` and exposes a single public initializer:

```rust
// contracts/nbtc/src/lib.rs:58-91
#[init]
pub fn new(
    controller: AccountId,
    bridge_id: AccountId,
    ...
) -> Self {
    require!(!env::state_exists(), "Already initialized");
    ...
}
``` [1](#0-0) 

The `#[init]` guard only prevents a second call once state exists. It does **not** restrict the caller. Any NEAR account can call `new()` on a freshly deployed, uninitialized nBTC contract.

The `controller` role is powerful. It grants access to:

```rust
// contracts/nbtc/src/migrate.rs:26-29
pub fn attach_full_access_key(&mut self, public_key: PublicKey) -> Promise {
    self.assert_controller();
    Promise::new(env::current_account_id()).add_full_access_key(public_key)
}
``` [2](#0-1) 

And:

```rust
// contracts/nbtc/src/migrate.rs:78-99
pub fn upgrade_and_migrate(&self) {
    self.assert_controller();
    ...
    env::promise_batch_action_deploy_contract(promise_id, &code);
    ...
}
``` [3](#0-2) 

The `mint()` function only checks that the caller is `bridge_id`:

```rust
// contracts/nbtc/src/lib.rs:332-334
fn assert_bridge(&self) {
    require!(self.bridge_id == env::predecessor_account_id(), "Not Allow");
}
``` [4](#0-3) 

The token migration flow in the bridge calls `mint()` on an operator-supplied `new_token` account without verifying that the token was initialized by a trusted party:

```rust
// contracts/satoshi-bridge/src/nbtc/migration.rs:84-100
let mut mint_batch = Promise::new(new_token.clone());
for (account, amount) in entries {
    mint_batch = mint_batch.function_call("mint".to_string(), args, ...);
}
``` [5](#0-4) 

If the migration succeeds, the bridge permanently switches its active token:

```rust
// contracts/satoshi-bridge/src/nbtc/migration.rs:119
self.internal_mut_config().nbtc_account_id = new_token.clone();
``` [6](#0-5) 

---

### Impact Explanation

**Critical.** If the attacker seizes `controller` on the new nBTC contract before the migration completes:

1. They call `attach_full_access_key()` to add their own key to the nBTC contract account.
2. Using that key, they deploy arbitrary replacement code (bypassing `upgrade_and_migrate`'s `migrate()` callback entirely, since a raw batch deploy from a full-access key has no such constraint).
3. The replacement code can expose an unrestricted `mint()`, allowing the attacker to mint arbitrary nBTC with no BTC backing.

Even without a code replacement, the attacker as `controller` can call `upgrade_and_migrate()` with crafted WASM whose `migrate()` function rewrites state to remove the `bridge_id` guard, achieving the same result.

The bridge's `migrate_to_new_token` succeeds (because `bridge_id` was set to the legitimate bridge contract), so `nbtc_account_id` is permanently updated to the attacker-controlled token. All subsequent bridge deposits mint into the compromised contract.

---

### Likelihood Explanation

**Medium.** The token migration is an infrequent but documented operational procedure. The test helper `deploy_new_token` and the integration test `test_migrate_to_new_token_success` both show the deployment and `new()` call as **separate transactions**:

```rust
// contracts/satoshi-bridge/tests/test_token_migration.rs:35-53
let contract = account.deploy(...).await...;
contract.call("new").args_json(...).transact().await...;
``` [7](#0-6) 

This confirms the expected operational pattern is non-atomic. An attacker watching the NEAR chain for a new nBTC contract deployment has a clear window — the gap between the `deploy` transaction and the `new()` transaction — to submit their own `new()` call. NEAR's transaction ordering within a block makes this a realistic front-run. The operator's subsequent `new()` call silently fails with "Already initialized," and if the operator does not verify the `controller` field before calling `migrate_to_new_token`, the attack succeeds.

---

### Recommendation

Deploy the nBTC contract and call `new()` atomically in a single batch transaction, exactly as `upgrade_and_migrate()` does for upgrades:

```rust
let promise_id = env::promise_batch_create(&new_token_account_id);
env::promise_batch_action_deploy_contract(promise_id, &nbtc_wasm);
env::promise_batch_action_function_call(promise_id, "new", init_args, NO_DEPOSIT, gas);
```

This eliminates the window between deployment and initialization. Additionally, `migrate_to_new_token` should verify that the new token's `controller` matches an expected trusted account before proceeding with the mint batch.

---

### Proof of Concept

1. Operator deploys a new nBTC contract at `nbtc2.near` (transaction T1).
2. Attacker observes T1 in the mempool/block and immediately submits a call to `nbtc2.near::new({ controller: "attacker.near", bridge_id: "bridge.near", ... })` (transaction T2).
3. T2 is included before the operator's own `new()` call (T3). T3 fails with "Already initialized."
4. Operator does not notice the failure and calls `bridge.near::migrate_to_new_token({ new_token: "nbtc2.near", accounts: [...] })`.
5. The bridge queries old-token balances, then calls `nbtc2.near::mint(...)` for each holder. `assert_bridge()` passes because `bridge_id == "bridge.near" == predecessor`.
6. `migrate_to_new_token_resolve` succeeds; `nbtc_account_id` is updated to `nbtc2.near`.
7. Attacker calls `nbtc2.near::attach_full_access_key({ public_key: <attacker_key> })` — passes `assert_controller()` since `controller == "attacker.near"`.
8. Attacker uses the full-access key to deploy malicious WASM to `nbtc2.near` with an unrestricted `mint()`.
9. Attacker mints arbitrary nBTC to any account, unbacked by BTC.

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

**File:** contracts/nbtc/src/lib.rs (L332-334)
```rust
    fn assert_bridge(&self) {
        require!(self.bridge_id == env::predecessor_account_id(), "Not Allow");
    }
```

**File:** contracts/nbtc/src/migrate.rs (L26-29)
```rust
    pub fn attach_full_access_key(&mut self, public_key: PublicKey) -> Promise {
        self.assert_controller();
        Promise::new(env::current_account_id()).add_full_access_key(public_key)
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

**File:** contracts/satoshi-bridge/src/nbtc/migration.rs (L84-100)
```rust
        let mut mint_batch = Promise::new(new_token.clone());
        for (account, amount) in entries {
            let args = serde_json::to_vec(&json!({
                "mint_account_id": account,
                "mint_amount": U128(amount),
                "protocol_fee": U128(0),
                "relayer_account_id": env::current_account_id(),
                "relayer_fee": U128(0),
                "post_actions": null,
            }))
            .unwrap_or_else(|_| env::panic_str("Failed to serialize mint args"));
            mint_batch = mint_batch.function_call(
                "mint".to_string(),
                args,
                NearToken::from_yoctonear(0),
                GAS_FOR_MINT_ACTION,
            );
```

**File:** contracts/satoshi-bridge/src/nbtc/migration.rs (L118-119)
```rust
        require!(is_promise_success(), "Migration mint failed");
        self.internal_mut_config().nbtc_account_id = new_token.clone();
```

**File:** contracts/satoshi-bridge/tests/test_token_migration.rs (L35-53)
```rust
    let contract = account
        .deploy(&std::fs::read("../../res/nbtc.wasm").unwrap())
        .await
        .unwrap()
        .unwrap();
    contract
        .call("new")
        .args_json(json!({
            "controller": context.root.id(),
            "bridge_id": context.bridge_contract.id(),
            "name": "Near BTC v2",
            "symbol": "NBTC2",
            "icon": null,
            "decimals": 8,
        }))
        .transact()
        .await
        .unwrap()
        .unwrap();
```
