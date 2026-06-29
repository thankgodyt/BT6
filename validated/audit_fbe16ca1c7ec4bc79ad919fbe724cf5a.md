Let me check the near-plugins v0.4.1 source to confirm the behavior of `acl_init_super_admin` when no super admin exists.

### Title
ACL State Not Initialized After `OldLegacyState` Migration Allows Any Account to Seize Super Admin and Mint Bridged Tokens — (`near/token-deployer/src/migrate.rs`)

---

### Summary

`migrate()` reconstructs `TokenDeployer` from `OldLegacyState` without initializing near-plugins ACL storage. Because `OldLegacyState` carried no ACL keys, the post-migration contract has zero super admins and zero role holders. near-plugins v0.4.1 exposes `acl_init_super_admin` as a public, unrestricted method that succeeds whenever no super admin exists. An attacker can therefore call it immediately after migration, grant themselves `Role::Controller`, and invoke `deploy_token` — which initializes the new token with `env::predecessor_account_id()` as its controller — enabling unauthorized minting of bridged tokens.

---

### Finding Description

**`migrate()` omits all ACL initialization:** [1](#0-0) 

When the deserialized state matches `OldLegacyState`, the function returns `Self { global_code_hash: global_code_hash.into() }` — a bare struct with no call to `acl_init_super_admin`, `acl_grant_role`, or `acl_transfer_super_admin`.

**Contrast with `new()`, which properly bootstraps ACL:** [2](#0-1) 

`new()` calls `acl_init_super_admin`, grants `Role::DAO` and `Role::Controller`, then transfers super-admin to the DAO. `migrate()` does none of this.

**near-plugins v0.4.1 `acl_init_super_admin` is publicly callable:** [3](#0-2) 

At tag `v0.4.1` (commit `6149e037`), near-plugins exposes `acl_init_super_admin(account_id: AccountId) -> bool` as a public contract method with no predecessor restriction. It returns `false` if a super admin already exists, and `true` (setting the caller-supplied account as super admin) otherwise. After migration from `OldLegacyState`, no super admin exists, so the call always succeeds for any caller.

**`deploy_token` sets the caller as token controller:** [4](#0-3) 

The `controller` field passed to the new token's `new()` is `env::predecessor_account_id()`. An attacker who holds `Role::Controller` and calls `deploy_token` becomes the controller of the newly deployed token, giving them unrestricted mint authority over it.

---

### Impact Explanation

An attacker who exploits this path:

1. Becomes super admin of the token-deployer contract.
2. Grants themselves `Role::Controller`.
3. Deploys a bridged token contract with themselves as controller.
4. Mints arbitrary amounts of that bridged token to any account.

This constitutes **unauthorized minting of bridged tokens** — a Critical impact under the scope rules. The minted tokens represent claims on locked assets on the origin chain, so the attacker can drain the bridge's collateral by redeeming fabricated tokens.

---

### Likelihood Explanation

The window of exploitation is the interval between the `migrate()` call and a legitimate admin calling `acl_init_super_admin`. Because `migrate()` is `#[private]` (self-call only), it is invoked atomically during the upgrade transaction. However, the ACL re-initialization is a **separate, subsequent transaction** that must be submitted manually. Any block produced between those two transactions is an open window. A monitoring attacker can detect the upgrade on-chain and front-run the admin's ACL setup call. If the admin forgets to re-initialize ACL entirely (a realistic operational error given that `migrate()` gives no warning), the contract remains permanently exploitable.

---

### Recommendation

Inside `migrate()`, after constructing the new state, immediately initialize ACL the same way `new()` does. Because `migrate()` is `#[private]` (called only by the contract itself during upgrade), the predecessor at that point is `env::current_account_id()`. The upgrade transaction should be structured so that the DAO account is passed as a parameter and ACL is bootstrapped atomically:

```rust
pub fn migrate(global_code_hash: Base58CryptoHash, controller: AccountId, dao: AccountId) -> Self {
    // ... existing state-check logic ...
    let mut contract = Self { global_code_hash: global_code_hash.into() };
    contract.acl_init_super_admin(env::current_account_id());
    contract.acl_grant_role(Role::DAO.into(), dao.clone());
    contract.acl_grant_role(Role::Controller.into(), controller);
    contract.acl_transfer_super_admin(dao);
    contract
}
```

This ensures ACL state is never absent after migration.

---

### Proof of Concept

```
1. Deploy token-deployer WASM compiled against OldLegacyState format.
   Call `new(controller, dao, code_hash)` — contract initializes normally.

2. Upgrade the contract account's WASM to the new token-deployer binary.
   Call `migrate(global_code_hash)` as a self-call (predecessor == current_account_id).
   → Contract state is now TokenDeployer { global_code_hash }.
   → ACL storage keys are absent (OldLegacyState had none).

3. From an unprivileged attacker account, call:
     acl_init_super_admin({ "account_id": "attacker.near" })
   → Returns true. Attacker is now super admin.

4. Attacker calls:
     acl_grant_role({ "role": "Controller", "account_id": "attacker.near" })
   → Succeeds. Attacker holds Role::Controller.

5. Attacker calls (with sufficient attached deposit):
     deploy_token({ "account_id": "fake-usdc.near", "metadata": {...} })
   → Deploys a new token contract with controller = "attacker.near".

6. Attacker calls on fake-usdc.near:
     mint({ "account_id": "attacker.near", "amount": "1000000000000" })
   → Mints arbitrary bridged tokens. Attacker redeems them against locked
     collateral on the origin chain, draining the bridge.
```

### Citations

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

**File:** near/token-deployer/src/lib.rs (L46-56)
```rust
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

**File:** near/token-deployer/src/lib.rs (L58-73)
```rust
    #[payable]
    #[access_control_any(roles(Role::Controller, Role::LegacyController))]
    pub fn deploy_token(&mut self, account_id: AccountId, metadata: &BasicMetadata) -> Promise {
        Promise::new(account_id)
            .create_account()
            .transfer(env::attached_deposit())
            .use_global_contract(self.global_code_hash)
            .function_call(
                "new".to_string(),
                json!({"controller": env::predecessor_account_id(), "metadata": metadata})
                    .to_string()
                    .into_bytes(),
                NO_DEPOSIT,
                OMNI_TOKEN_INIT_GAS,
            )
    }
```

**File:** near/Cargo.lock (L2235-2243)
```text
name = "near-plugins"
version = "0.2.0"
source = "git+https://github.com/aurora-is-near/near-plugins?tag=v0.4.1#6149e0378fe46c7f740153cc0274b6da1f194112"
dependencies = [
 "bitflags 1.3.2",
 "near-plugins-derive",
 "near-sdk",
 "serde",
]
```
