### Title
Missing ACL Role Initialization in `migrate()` Permanently Freezes `deploy_token` and `set_global_code_hash` — (`near/token-deployer/src/migrate.rs`)

### Summary

The `migrate()` function in the NEAR token-deployer contract constructs a fresh `TokenDeployer` state without calling `acl_init_super_admin`, `acl_grant_role`, or `acl_transfer_super_admin`. As a result, after a valid migration from `OldLegacyState`, no account holds `Controller`, `LegacyController`, or `DAO` roles, and no super-admin exists. Both `deploy_token` and `set_global_code_hash` are gated behind those roles and become permanently inaccessible, blocking all future bridged-token deployments on NEAR.

### Finding Description

`new()` correctly initializes the ACL system: [1](#0-0) 

```rust
contract.acl_init_super_admin(near_sdk::env::predecessor_account_id());
contract.acl_grant_role(Role::DAO.into(), dao.clone());
contract.acl_grant_role(Role::Controller.into(), controller);
contract.acl_transfer_super_admin(dao);
```

`migrate()` does none of this — it only sets `global_code_hash`: [2](#0-1) 

```rust
Self {
    global_code_hash: global_code_hash.into(),
}
```

The two protected functions require roles that are never assigned: [3](#0-2) 

```rust
#[access_control_any(roles(Role::Controller, Role::LegacyController))]
pub fn deploy_token(...)
``` [4](#0-3) 

```rust
#[access_control_any(roles(Role::DAO))]
pub fn set_global_code_hash(...)
```

The `OldLegacyState` (rainbow-bridge legacy deployer) never used `near-plugins`, so no ACL storage keys exist before migration. After `migrate()` completes, the ACL storage is empty: no super-admin, no Controller, no LegacyController, no DAO. [5](#0-4) 

Because `near-plugins` stores ACL data in contract storage independently of the main `STATE` key, and `migrate()` uses `#[init(ignore_state)]` which only replaces the main state, the ACL storage remains uninitialized after migration.

### Impact Explanation

The NEAR omni-bridge calls `deploy_token` on the deployer contract via `deploy_token_internal`: [6](#0-5) 

Every call to `ext_deployer::ext(deployer).deploy_token(...)` will revert with an ACL error because no account holds `Controller` or `LegacyController`. This blocks `fin_transfer` for every token not yet deployed, making the bridge permanently non-functional for new assets on all chains routed through this deployer (EVM, Solana, Starknet, Bitcoin, Zcash, Wormhole).

Additionally, `set_global_code_hash` is inaccessible (no DAO role), so the global contract hash for token deployments can never be updated.

### Likelihood Explanation

The migration path is explicitly coded for production use (migrating from the rainbow-bridge legacy deployer). Any operator following the documented upgrade path — deploy legacy WASM, initialize `OldLegacyState`, deploy new WASM, call `migrate()` — will trigger this condition. The `#[private]` guard only requires the call to come from the deployer account itself, which is the normal migration pattern. The bug is deterministic and reproducible on every migration from `OldLegacyState`.

### Recommendation

Inside `migrate()`, after constructing `Self`, call the same ACL initialization sequence used in `new()`. The `migrate()` function should accept `controller` and `dao` parameters (or read them from the old state if available) and call:

```rust
contract.acl_init_super_admin(env::predecessor_account_id());
contract.acl_grant_role(Role::DAO.into(), dao.clone());
contract.acl_grant_role(Role::Controller.into(), controller);
contract.acl_transfer_super_admin(dao);
``` [7](#0-6) 

### Proof of Concept

Using `near-workspaces` sandbox:

1. Deploy the legacy rainbow-bridge token-deployer WASM and call `new(prover_account, locker_address)` — this populates `OldLegacyState`.
2. Deploy the new `TokenDeployer` WASM over the same account.
3. Call `migrate(global_code_hash)` from the deployer account (satisfies `#[private]`).
4. Assert `acl_has_role("Controller", bridge_account)` returns `false`.
5. Assert `acl_has_role("LegacyController", bridge_account)` returns `false`.
6. Assert `acl_has_role("DAO", any_account)` returns `false`.
7. Call `deploy_token(token_account_id, metadata)` from any account including the bridge contract — assert it panics with an ACL error.
8. Call `set_global_code_hash(new_hash)` from any account — assert it panics with an ACL error.

All assertions pass on unmodified code, confirming the invariant is broken after every migration from `OldLegacyState`.

### Citations

**File:** near/token-deployer/src/lib.rs (L51-54)
```rust
        contract.acl_init_super_admin(near_sdk::env::predecessor_account_id());
        contract.acl_grant_role(Role::DAO.into(), dao.clone());
        contract.acl_grant_role(Role::Controller.into(), controller);
        contract.acl_transfer_super_admin(dao);
```

**File:** near/token-deployer/src/lib.rs (L58-60)
```rust
    #[payable]
    #[access_control_any(roles(Role::Controller, Role::LegacyController))]
    pub fn deploy_token(&mut self, account_id: AccountId, metadata: &BasicMetadata) -> Promise {
```

**File:** near/token-deployer/src/lib.rs (L79-81)
```rust
    #[access_control_any(roles(Role::DAO))]
    pub fn set_global_code_hash(&mut self, global_code_hash: Base58CryptoHash) {
        self.global_code_hash = global_code_hash.into();
```

**File:** near/token-deployer/src/migrate.rs (L14-23)
```rust
#[derive(BorshDeserialize, BorshSerialize)]
pub struct OldLegacyState {
    pub prover_account: AccountId,
    pub locker_address: [u8; 20],
    pub tokens: UnorderedSet<String>,
    pub used_events: UnorderedSet<Vec<u8>>,
    pub owner_pk: PublicKey,
    pub bridge_token_storage_deposit_required: u128,
    paused: u128,
}
```

**File:** near/token-deployer/src/migrate.rs (L29-46)
```rust
    pub fn migrate(global_code_hash: Base58CryptoHash) -> Self {
        if !env::state_exists() {
            env::panic_str("Old state not found. Migration is not needed.")
        }

        let state = env::storage_read(STATE_KEY)
            .unwrap_or_else(|| env::panic_str("Failed to read state key."));

        if OldState::try_from_slice(&state).is_ok()
            || OldLegacyState::try_from_slice(&state).is_ok()
        {
            Self {
                global_code_hash: global_code_hash.into(),
            }
        } else {
            env::panic_str("Old state not found. Migration is not needed.")
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L2446-2453)
```rust
        ext_deployer::ext(deployer)
            .with_static_gas(DEPLOY_TOKEN_GAS)
            .with_attached_deposit(attached_deposit.saturating_sub(required_deposit))
            .deploy_token(token_id.clone(), metadata)
            .then(
                Self::ext(env::current_account_id())
                    .deploy_token_by_deployer_callback(token_address, token_id),
            )
```
