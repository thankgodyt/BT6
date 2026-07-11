### Title
Immutable `bridge_id` in nbtc Contract Prevents Revocation of Minting Authority - (File: `contracts/nbtc/src/lib.rs`)

### Summary
The `nbtc` token contract stores the authorized bridge address in an immutable `bridge_id` field. There is no function allowing the `controller` to update or revoke this field. If the `satoshi-bridge` contract must be migrated to a new account ID, the old bridge retains permanent minting and burning authority over `nBTC`, and the new bridge cannot be authorized without a full contract code upgrade.

### Finding Description
The `nbtc` contract's `Contract` struct stores `bridge_id` as a plain field set once at construction: [1](#0-0) 

The `bridge_id` is the sole gatekeeper for `mint`, `burn`, and `safe_mint`: [2](#0-1) [3](#0-2) [4](#0-3) 

The only administrative setter exposed by the contract is `set_controller`, which changes the `controller` field only: [5](#0-4) 

No `set_bridge_id` function exists anywhere in `contracts/nbtc/src/lib.rs` or `contracts/nbtc/src/migrate.rs`. The `migrate()` function simply deserializes and returns the existing state unchanged, preserving the old `bridge_id`: [6](#0-5) 

The `upgrade_and_migrate` path deploys new code and calls `migrate()`, but the current `migrate()` does not accept a new `bridge_id` parameter, so even a code upgrade leaves the old value in place unless the operator writes and deploys entirely new migration logic: [7](#0-6) 

By contrast, the `satoshi-bridge` contract correctly initializes its access control system and provides explicit `add_super_admin`/`remove_super_admin` and `extend_operators`/`remove_operators` functions to grant and revoke roles at any time: [8](#0-7) [9](#0-8) 

The `nbtc` contract has no equivalent revocation path for `bridge_id`.

### Impact Explanation
If the `satoshi-bridge` contract must be replaced at a new account ID (e.g., due to a critical bug, a required state migration that cannot be done in-place, or a governance decision), the `controller` of the `nbtc` contract has no direct mechanism to authorize the new bridge or deauthorize the old one. The old bridge address retains permanent `mint`/`burn` authority. The only remediation path is to write, audit, and deploy entirely new contract code via `upgrade_and_migrate` — a complex, time-pressured operation that itself carries risk. During any window between discovery and successful code upgrade, the old bridge retains full minting authority. This maps to: **Medium — stuck bridge state requiring operator intervention; bypass of bridge migration controls**.

### Likelihood Explanation
The `satoshi-bridge` contract is designed for in-place upgrades via the `Upgradable` plugin (same account ID), so the common upgrade path does not trigger this issue. However, the scenario is realistic whenever a critical vulnerability in the bridge contract forces deployment to a new account, or when governance decides to migrate the bridge to a new contract. The `migrate_to_new_token` flow in the bridge handles migrating to a new *token* contract but does not address migrating to a new *bridge* contract. The absence of a `set_bridge_id` function is a straightforward omission with no compensating control.

### Recommendation
Add a `set_bridge_id` function to `contracts/nbtc/src/lib.rs`, protected by `assert_controller` and `assert_one_yocto`, analogous to the existing `set_controller`:

```rust
#[payable]
pub fn set_bridge_id(&mut self, bridge_id: AccountId) {
    assert_one_yocto();
    self.assert_controller();
    // Re-register the new bridge for storage
    if self.token.accounts.get(&bridge_id).is_none() {
        self.token.internal_register_account(&bridge_id);
    }
    self.bridge_id = bridge_id;
}
```

This mirrors the fix recommended in the external report: grant the administrative account the ability to change the privileged role, so it can be revoked or transferred for deprecation and migration purposes.

### Proof of Concept
1. Deploy `nbtc` with `bridge_id = "satoshi-bridge-v1.near"`.
2. A critical bug is found in `satoshi-bridge-v1.near`; a new contract `satoshi-bridge-v2.near` is deployed.
3. The `controller` calls `set_controller` — succeeds, controller is updated.
4. The `controller` attempts to authorize `satoshi-bridge-v2.near` as the new bridge — **no such function exists; call fails**.
5. `satoshi-bridge-v1.near` retains the ability to call `mint` and `burn` on the `nbtc` contract indefinitely.
6. `satoshi-bridge-v2.near` cannot call `mint` or `burn` and is permanently blocked from operating. [10](#0-9)

### Citations

**File:** contracts/nbtc/src/lib.rs (L22-29)
```rust
#[derive(PanicOnDefault)]
#[near(contract_state)]
pub struct Contract {
    controller: AccountId,
    bridge_id: AccountId,
    token: FungibleToken,
    metadata: LazyOption<FungibleTokenMetadata>,
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

**File:** contracts/nbtc/src/lib.rs (L107-107)
```rust
        self.assert_bridge();
```

**File:** contracts/nbtc/src/lib.rs (L135-135)
```rust
        self.assert_bridge();
```

**File:** contracts/nbtc/src/lib.rs (L157-157)
```rust
        self.assert_bridge();
```

**File:** contracts/nbtc/src/lib.rs (L331-334)
```rust
impl Contract {
    fn assert_bridge(&self) {
        require!(self.bridge_id == env::predecessor_account_id(), "Not Allow");
    }
```

**File:** contracts/nbtc/src/migrate.rs (L31-35)
```rust
    #[private]
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        env::state_read().unwrap_or_else(|| env::panic_str("ERR_FAILED_TO_READ_STATE"))
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

**File:** contracts/satoshi-bridge/src/lib.rs (L220-223)
```rust
        contract.acl_init_super_admin(env::predecessor_account_id());
        contract.acl_grant_role(Role::DAO.into(), env::predecessor_account_id());
        contract.acl_grant_role(Role::PauseManager.into(), env::predecessor_account_id());
        contract.acl_grant_role(Role::UnpauseManager.into(), env::predecessor_account_id());
```

**File:** contracts/satoshi-bridge/src/api/management.rs (L57-77)
```rust
    #[payable]
    #[access_control_any(roles(Role::DAO))]
    pub fn remove_super_admin(&mut self, account_id: AccountId) {
        assert_one_yocto();
        require!(
            env::predecessor_account_id() != account_id,
            "cannot remove oneself"
        );
        let is_success = self
            .acl_revoke_role(Role::DAO.into(), account_id.clone())
            .unwrap();
        require!(is_success, "acl_revoke_role DAO failed");
        let is_success = self
            .acl_revoke_role(Role::PauseManager.into(), account_id.clone())
            .unwrap();
        require!(is_success, "acl_revoke_role PauseManager failed");
        // Accounts created before UnpauseManager existed may not hold this role; tolerate that.
        self.acl_revoke_role(Role::UnpauseManager.into(), account_id.clone());
        let is_success = self.acl_revoke_super_admin(account_id.clone()).unwrap();
        require!(is_success, "acl_revoke_super_admin failed");
    }
```
