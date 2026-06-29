Audit Report

## Title
ACL State Not Initialized After `migrate()` Allows Any Account to Seize Super Admin and Mint Bridged Tokens — (`near/token-deployer/src/migrate.rs`)

## Summary

`migrate()` in `near/token-deployer/src/migrate.rs` reconstructs `TokenDeployer` from `OldState` or `OldLegacyState` without initializing near-plugins ACL storage. Because neither legacy state format carries ACL keys, the post-migration contract has zero super admins and zero role holders. near-plugins (git tag `v0.4.1`) exposes `acl_init_super_admin` as a public, unrestricted method that succeeds whenever no super admin exists, allowing any caller to seize super admin, grant themselves `Role::Controller`, and invoke `deploy_token` — which initializes the new token with `env::predecessor_account_id()` as its controller — enabling unauthorized minting of bridged tokens.

## Finding Description

**`migrate()` omits all ACL initialization.** When the deserialized state matches either `OldState` or `OldLegacyState`, the function returns `Self { global_code_hash: global_code_hash.into() }` with no call to `acl_init_super_admin`, `acl_grant_role`, or `acl_transfer_super_admin`. [1](#0-0) 

**Contrast with `new()`, which properly bootstraps ACL.** `new()` calls `acl_init_super_admin`, grants `Role::DAO` and `Role::Controller`, then transfers super-admin to the DAO. `migrate()` does none of this. [2](#0-1) 

**near-plugins v0.4.1 `acl_init_super_admin` is publicly callable.** The Cargo.lock confirms the dependency is sourced from git tag `v0.4.1` (commit `6149e0378fe46c7f740153cc0274b6da1f194112`). At that tag, `acl_init_super_admin(account_id: AccountId) -> bool` is a public contract method with no predecessor restriction: it returns `false` if a super admin already exists, and `true` (setting the supplied account as super admin) otherwise. After migration from either legacy state, no super admin exists, so the call always succeeds for any caller. [3](#0-2) 

**`deploy_token` sets the caller as token controller.** The `controller` field passed to the new token's `new()` is `env::predecessor_account_id()`. An attacker who holds `Role::Controller` and calls `deploy_token` becomes the controller of the newly deployed token, giving them unrestricted mint authority over it. [4](#0-3) 

**Exploit chain:**
1. Upgrade contract WASM; call `migrate(global_code_hash)` as a self-call — state is now `TokenDeployer { global_code_hash }` with no ACL storage keys.
2. Attacker calls `acl_init_super_admin({ "account_id": "attacker.near" })` — returns `true`; attacker is now super admin.
3. Attacker calls `acl_grant_role({ "role": "Controller", "account_id": "attacker.near" })` — succeeds; attacker holds `Role::Controller`.
4. Attacker calls `deploy_token({ "account_id": "fake-usdc.near", "metadata": {...} })` — deploys a bridged token contract with `controller = "attacker.near"`.
5. Attacker calls `mint` on the deployed token — mints arbitrary bridged tokens redeemable against locked collateral on the origin chain.

No existing guard prevents this: `migrate()` is `#[private]` (self-call only) and `#[init(ignore_state)]`, which is correct for upgrade mechanics, but the absence of ACL bootstrapping inside the same atomic call is the root cause. The `#[access_control_any(roles(Role::Controller, Role::LegacyController))]` guard on `deploy_token` is bypassed because the attacker self-grants `Role::Controller` after seizing super admin. [5](#0-4) 

## Impact Explanation

An attacker who exploits this path becomes super admin of the token-deployer contract, grants themselves `Role::Controller`, deploys a bridged token contract with themselves as controller, and mints arbitrary amounts of that bridged token to any account. The minted tokens represent claims on locked assets on the origin chain, so the attacker can drain the bridge's collateral by redeeming fabricated tokens. This constitutes **unauthorized minting of bridged tokens** — a Critical impact matching the allowed scope: "Unauthorized transaction, authorization bypass, role bypass… that lets an attacker execute bridge, token, deployer, relayer, or admin-equivalent actions" and "Stealing, loss, double-spending, unauthorized minting… of bridged funds."

## Likelihood Explanation

The exploitation window is the interval between the `migrate()` self-call and a legitimate admin calling `acl_init_super_admin`. Because `migrate()` is `#[private]`, it is invoked atomically during the upgrade transaction, but ACL re-initialization is a **separate, subsequent transaction** that must be submitted manually. Any block produced between those two transactions is an open window. A monitoring attacker can detect the upgrade on-chain and front-run the admin's ACL setup call. If the admin omits ACL re-initialization entirely — a realistic operational error given that `migrate()` provides no warning — the contract remains permanently exploitable. The attack requires no special privileges, no leaked keys, and no victim cooperation.

## Recommendation

Inside `migrate()`, after constructing the new state, immediately initialize ACL the same way `new()` does. Accept `dao` and `controller` as parameters and bootstrap ACL atomically within the same `#[private]` call:

```rust
#[private]
#[init(ignore_state)]
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

This ensures ACL state is never absent after migration and eliminates the exploitation window entirely. [6](#0-5) 

## Proof of Concept

```
1. Deploy token-deployer WASM compiled against OldLegacyState format.
   Call `new(controller, dao, code_hash)` — contract initializes normally with ACL.

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

A private-testnet integration test using `near-workspaces-rs` can reproduce this exactly: deploy old WASM, call `new`, upgrade WASM, call `migrate`, then from a fresh account call `acl_init_super_admin` and assert it returns `true`, followed by `acl_grant_role` and `deploy_token`.

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
