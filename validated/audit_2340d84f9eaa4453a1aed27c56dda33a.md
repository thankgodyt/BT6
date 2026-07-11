### Title
Malicious DAO Member Can Front-Run `remove_super_admin()` to Permanently Retain DAO Privileges - (File: contracts/satoshi-bridge/src/api/management.rs)

---

### Summary

Any DAO member can call `add_super_admin()` to grant full DAO privileges to arbitrary accounts. Because `remove_super_admin()` only revokes one account at a time and there is no atomic "revoke all" mechanism, a malicious DAO member can front-run their own removal by pre-authorizing a controlled account, then use that account to re-grant themselves DAO access — creating an irrevocable cycle identical to the Caller contract vulnerability in the reference report.

---

### Finding Description

`add_super_admin()` is gated only by `#[access_control_any(roles(Role::DAO))]`, meaning **every** DAO member — not just the original deployer — can promote any arbitrary account to full DAO super-admin status:

```rust
// contracts/satoshi-bridge/src/api/management.rs
#[payable]
#[access_control_any(roles(Role::DAO))]
pub fn add_super_admin(&mut self, account_id: AccountId) {
    assert_one_yocto();
    let is_success = self.acl_add_super_admin(account_id.clone()).unwrap();
    ...
    self.acl_grant_role(Role::DAO.into(), account_id.clone())...
    self.acl_grant_role(Role::PauseManager.into(), account_id.clone())...
    self.acl_grant_role(Role::UnpauseManager.into(), account_id.clone())...
}
```

`remove_super_admin()` revokes a single account and has no batch or "revoke all" variant:

```rust
#[payable]
#[access_control_any(roles(Role::DAO))]
pub fn remove_super_admin(&mut self, account_id: AccountId) {
    assert_one_yocto();
    require!(env::predecessor_account_id() != account_id, "cannot remove oneself");
    self.acl_revoke_role(Role::DAO.into(), account_id.clone())...
    self.acl_revoke_super_admin(account_id.clone())...
}
```

**Attack sequence (analog to Alice/Bob/Eve in the reference report):**

1. DAO governance decides to remove malicious DAO member **Bob** and submits `remove_super_admin(Bob)`.
2. Bob observes the pending transaction and front-runs it by calling `add_super_admin(Eve)`, where **Eve** is a fresh NEAR account Bob controls.
3. `remove_super_admin(Bob)` executes — Bob loses DAO access.
4. Bob calls `add_super_admin(Bob)` from Eve's account — Bob regains full DAO access.
5. Repeat indefinitely: Bob can keep creating new NEAR accounts (cheap on NEAR) and granting them DAO access, forcing governance into an endless revocation battle.

Even without strict mempool front-running (NEAR lacks a gas-price auction), Bob can proactively grant DAO to multiple controlled accounts **before** any removal attempt, achieving the same persistent-access outcome without any race condition.

---

### Impact Explanation

DAO is the root-of-trust role in this bridge. It controls:
- `withdraw_protocol_fee` — direct drain of accumulated protocol fees
- `update_config` — change bridge parameters (fees, limits, addresses)
- `extend_operators` / `extend_relayer_white_list` — inject malicious operators or relayers
- Upgrade functions (`UpgradableCodeStager`, `UpgradableCodeDeployer` also granted to DAO) — deploy arbitrary replacement contract code

A malicious DAO member who cannot be permanently removed can steal protocol funds, redirect bridge outputs, or deploy a malicious upgrade — matching **Critical: Bypass of bridge authorization/upgrade controls with real security impact** and **Critical: Significant loss or theft of protocol funds**.

---

### Likelihood Explanation

Medium. The attack requires a DAO member to turn malicious after being legitimately granted access — the same precondition as the reference report (authorized user becomes malicious). Once that precondition is met, the exploit is trivial: create a fresh NEAR account, call `add_super_admin` once, and the removal is permanently defeatable. No cryptographic capability, no external dependency, and no special timing beyond submitting one transaction before the removal lands.

---

### Recommendation

1. **Add an atomic `revoke_all_super_admins` / `emergency_revoke` function** callable by a quorum of remaining DAO members (or a dedicated `EmergencyAdmin` role) that clears the entire super-admin and DAO grantee list in one transaction, analogous to the `unauthorizeAll` suggestion in the reference report.

2. **Alternatively, restrict `add_super_admin` to a single designated root account** (e.g., the deployer or a multisig) rather than allowing any DAO member to promote others, breaking the self-perpetuating cycle.

3. **At minimum, emit an on-chain event** for every `add_super_admin` call so governance tooling can detect and batch-revoke newly added accounts before they are used.

---

### Proof of Concept

```
// Pseudocode — NEAR transaction sequence

// Step 1: Governance submits removal (in flight)
alice.call("remove_super_admin", { account_id: "bob.near" })

// Step 2: Bob front-runs (or pre-emptively executes before any removal attempt)
bob.call("add_super_admin", { account_id: "eve.near" })
// Eve is a fresh account controlled by Bob

// Step 3: Alice's removal lands — Bob loses DAO
// remove_super_admin(bob.near) executes successfully

// Step 4: Bob regains DAO via Eve
eve.call("add_super_admin", { account_id: "bob.near" })
// Bob is now DAO again; repeat from Step 2 as needed
```

Root cause references: [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** contracts/satoshi-bridge/src/api/management.rs (L34-55)
```rust
    #[payable]
    #[access_control_any(roles(Role::DAO))]
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
