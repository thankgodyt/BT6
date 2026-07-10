### Title
Incomplete Role Revocation in `remove_super_admin` Leaves Residual Upgrade Permissions After DAO Rotation - (File: contracts/satoshi-bridge/src/api/management.rs)

### Summary

The `remove_super_admin` function only revokes three roles (`DAO`, `PauseManager`, `UnpauseManager`) and super-admin status. It does not revoke `Role::UpgradableCodeStager`, `Role::UpgradableCodeDeployer`, `Role::MigrationOperator`, `Role::RefundOperator`, `Role::RelayerManager`, or `Role::UnrestrictedRelayer`. If any of these were granted to the account being removed — a natural operational practice for a DAO account — they persist silently after removal. The most critical residual roles are `UpgradableCodeStager` + `UpgradableCodeDeployer`, which together allow the removed account to stage and deploy an arbitrary contract upgrade, bypassing the bridge's upgrade authorization controls entirely.

### Finding Description

`remove_super_admin` is the bridge's mechanism for rotating DAO governance — removing a former administrator's privileges. Its implementation is: [1](#0-0) 

It revokes exactly: `Role::DAO`, `Role::PauseManager`, `Role::UnpauseManager` (silently, ignoring failure on line 74), and super-admin status. The `Contract` struct is decorated with the `near-plugins` `Upgradable` trait: [2](#0-1) 

This configuration means `Role::UpgradableCodeStager` and `Role::UpgradableCodeDeployer` are independent roles that authorize code staging and deployment respectively. They are never touched by `remove_super_admin`. Similarly, `Role::MigrationOperator`, `Role::RefundOperator`, `Role::RelayerManager`, and `Role::UnrestrictedRelayer` are defined in the `Role` enum: [3](#0-2) 

None of these are revoked during super-admin removal. In contrast, `add_super_admin` only grants DAO, PauseManager, and UnpauseManager: [4](#0-3) 

So the asymmetry is not between `add_super_admin` and `remove_super_admin` alone — it is between the full set of roles a DAO account accumulates over its operational lifetime and the narrow set that `remove_super_admin` cleans up.

### Impact Explanation

A removed DAO account retaining `Role::UpgradableCodeStager` + `Role::UpgradableCodeDeployer` can:

1. Call `up_stage_code(...)` to stage arbitrary WASM bytecode.
2. Call `up_deploy_code(...)` after any configured timelock to deploy it.

This is a complete bypass of upgrade authorization controls. A malicious upgrade could redirect all bridge funds, disable verification, or mint unbacked nBTC/nZEC. This falls squarely within the allowed critical impact: **"Bypass of bridge verification, authorization, migration, or upgrade controls with real security impact."**

Residual `Role::MigrationOperator` could additionally allow unauthorized token migration operations. Residual `Role::RefundOperator` allows the removed account to reject legitimate user refund requests or fast-track refund execution (bypassing the `unsafe_refund_timelock_sec`): [5](#0-4) 

### Likelihood Explanation

DAO accounts in production bridge deployments are routinely granted all operationally relevant roles, including upgrade roles, to enable governance flexibility. When DAO rotation occurs (a common lifecycle event — key compromise, team change, multisig migration), the operator calls `remove_super_admin` expecting full privilege removal. The incomplete cleanup is non-obvious: the function succeeds, emits no warning, and the residual roles are invisible without an off-chain ACL audit. The removed account can then exploit residual roles at any future time.

### Recommendation

`remove_super_admin` should revoke **all** roles defined in the `Role` enum before revoking super-admin status:

```rust
pub fn remove_super_admin(&mut self, account_id: AccountId) {
    assert_one_yocto();
    require!(env::predecessor_account_id() != account_id, "cannot remove oneself");

    // Revoke every role unconditionally (ignore "did not hold" failures)
    for role in [
        Role::DAO, Role::PauseManager, Role::UnpauseManager,
        Role::Operator, Role::UpgradableCodeStager, Role::UpgradableCodeDeployer,
        Role::UnrestrictedRelayer, Role::RelayerManager,
        Role::RefundOperator, Role::MigrationOperator,
    ] {
        self.acl_revoke_role(role.into(), account_id.clone());
    }
    let is_success = self.acl_revoke_super_admin(account_id.clone()).unwrap();
    require!(is_success, "acl_revoke_super_admin failed");
}
```

Alternatively, enumerate all roles from a single source of truth so future role additions are automatically covered by removal.

### Proof of Concept

1. Current DAO (`dao.near`) calls `extend_operators`, grants `UpgradableCodeStager` and `UpgradableCodeDeployer` to `old_admin.near` for upgrade management.
2. `dao.near` calls `add_super_admin(old_admin.near)` — grants DAO, PauseManager, UnpauseManager.
3. Governance decides to rotate: `dao.near` calls `remove_super_admin(old_admin.near)`.
4. `remove_super_admin` revokes DAO, PauseManager, UnpauseManager, super-admin. **Does not touch `UpgradableCodeStager` or `UpgradableCodeDeployer`.**
5. `old_admin.near` (now removed from governance) calls `up_stage_code(malicious_wasm)` — succeeds because `UpgradableCodeStager` is still held.
6. After the upgrade timelock, `old_admin.near` calls `up_deploy_code()` — succeeds because `UpgradableCodeDeployer` is still held.
7. Malicious contract is live; bridge funds are at risk. [1](#0-0) [2](#0-1)

### Citations

**File:** contracts/satoshi-bridge/src/api/management.rs (L36-55)
```rust
    pub fn add_super_admin(&mut self, account_id: AccountId) {
        assert_one_yocto();
        let is_success = self.acl_add_super_admin(account_id.clone()).unwrap();
        require!(is_success, "acl_add_super_admin failed");
        let is_success = self
            .acl_grant_role(Role::DAO.into(), account_id.clone())
            .unwrap();
        require!(is_success, "acl_grant_role DAO failed");
        let is_success = self
            .acl_grant_role(Role::PauseManager.into(), account_id.clone())
            .unwrap();
        require!(is_success, "acl_grant_role PauseManager failed");
        let is_success = self
            .acl_grant_role(Role::UnpauseManager.into(), account_id.clone())
            .unwrap();
        require!(is_success, "acl_grant_role UnpauseManager failed");
        if !self.check_account_exists(&account_id) {
            self.internal_set_account(&account_id, Account::new(&account_id));
        }
    }
```

**File:** contracts/satoshi-bridge/src/api/management.rs (L59-77)
```rust
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

**File:** contracts/satoshi-bridge/src/lib.rs (L101-114)
```rust
#[derive(AccessControlRole, Deserialize, Serialize, Copy, Clone)]
#[serde(crate = "near_sdk::serde")]
pub enum Role {
    DAO,
    Operator,
    PauseManager,
    UpgradableCodeStager,
    UpgradableCodeDeployer,
    UnrestrictedRelayer,
    RelayerManager,
    RefundOperator,
    UnpauseManager,
    MigrationOperator,
}
```

**File:** contracts/satoshi-bridge/src/lib.rs (L164-170)
```rust
#[upgradable(access_control_roles(
    code_stagers(Role::UpgradableCodeStager, Role::DAO),
    code_deployers(Role::UpgradableCodeDeployer, Role::DAO),
    duration_initializers(Role::DAO),
    duration_update_stagers(Role::DAO),
    duration_update_appliers(Role::DAO),
))]
```

**File:** contracts/satoshi-bridge/src/refund.rs (L206-228)
```rust
        let caller = env::predecessor_account_id();
        let is_privileged =
            self.acl_has_any_role(vec![Role::DAO.into(), Role::RefundOperator.into()], caller);
        let refund_request: RefundRequest = self
            .data()
            .refund_requests
            .get(utxo_storage_key)
            .expect("Refund request not found")
            .into();
        let config = self.internal_config();
        if refund_request.deposit_msg().refund_address.is_some() {
            // Pre-authorized refund address: privileged users can fast-track.
            if is_privileged {
                0
            } else {
                config.refund_timelock_sec
            }
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
    }
```
