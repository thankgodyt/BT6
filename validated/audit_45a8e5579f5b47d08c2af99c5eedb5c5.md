### Title
`reject_refund` Missing `#[pause]` Guard Allows State Mutation During Emergency Pause - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
The `reject_refund` function in the `satoshi-bridge` contract is the only state-changing public function in the bridge API that lacks the `#[pause(except(roles(Role::DAO)))]` decorator. Every other state-mutating function in the same file carries this guard. As a result, pausing the contract does not prevent `reject_refund` from being called, including via its permissionless path that any unprivileged NEAR account can trigger.

### Finding Description
The `Contract` struct derives `Pausable` from `near-plugins` and all critical bridge operations are decorated with `#[pause(except(roles(Role::DAO)))]`. [1](#0-0) 

Every state-changing function in `bridge.rs` carries this guard — `verify_deposit`, `verify_deposit_v2`, `request_refund`, `execute_refund`, `verify_refund_finalize`, `withdraw_rbf`, `claim_lost_found`, etc. — except `reject_refund`: [2](#0-1) 

`reject_refund` has a permissionless execution path: when `is_already_deposited` is `true` (the UTXO is present in `verified_deposit_utxo` and the request's `executed` flag is `false`), any caller can invoke it without holding `DAO` or `Operator` roles. [3](#0-2) 

The internal effect is unconditional removal of the refund request from contract storage: [4](#0-3) 

### Impact Explanation
When the bridge is paused in response to a security incident, the intent is to freeze all state changes. Because `reject_refund` bypasses the pause check, an unprivileged account can still mutate bridge state during a pause by deleting refund requests whose UTXO was already recorded in `verified_deposit_utxo`. This violates the pause invariant that every other state-changing function upholds, and removes a user's only on-chain record of a pending refund. In an incident scenario where the pause was triggered precisely because a deposit was fraudulently verified (e.g., a light-client compromise), the refund request is the user's recovery path; its deletion during the pause permanently forecloses that path without operator intervention to recreate it.

**Impact: Low** — publicly reachable invariant-violation in a production bridge path; no direct theft in the common case, but the pause guarantee is broken and user refund state can be destroyed during an emergency window.

### Likelihood Explanation
The permissionless trigger condition (`is_already_deposited == true`) requires a UTXO to have been finalized via `verify_deposit` while a refund request for the same UTXO still exists with `executed == false`. This co-occurrence is uncommon in normal operation but is precisely the state that exists when a deposit races a refund request. An attacker monitoring on-chain state can detect this condition and call `reject_refund` at any time, including during a pause.

### Recommendation
Add `#[pause(except(roles(Role::DAO)))]` to `reject_refund`, consistent with every other state-changing function in the bridge API:

```rust
#[pause(except(roles(Role::DAO)))]
pub fn reject_refund(&mut self, utxo_storage_key: String) {
    ...
}
```

### Proof of Concept
1. User calls `request_refund` for UTXO `txid@0`; refund request stored with `executed = false`.
2. A relayer calls `verify_deposit_v2` for the same UTXO; `verified_deposit_utxo` now contains `txid@0`.
3. `PauseManager` calls `pa_pause_feature("ALL")` — all guarded functions revert.
4. Attacker calls `reject_refund("txid@0")`:
   - `is_privileged = false` (attacker holds no role)
   - `executed = false`, `verified_deposit_utxo.contains("txid@0") = true` → `is_already_deposited = true`
   - `require!(is_privileged || is_already_deposited, ...)` passes
   - `internal_reject_refund` removes the refund request from storage
5. The call succeeds despite the contract being fully paused, permanently deleting the user's refund record. [2](#0-1) [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/lib.rs (L161-163)
```rust
#[derive(Pausable, Upgradable, PanicOnDefault)]
#[access_control(role_type(Role))]
#[pausable(pause_roles(Role::PauseManager), unpause_roles(Role::UnpauseManager))]
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L544-569)
```rust
    pub fn reject_refund(&mut self, utxo_storage_key: String) {
        let caller = env::predecessor_account_id();
        let is_privileged = self.acl_has_role(Role::DAO.into(), caller.clone())
            || self.acl_has_role(Role::Operator.into(), caller);
        // `execute_refund` also inserts the UTXO into `verified_deposit_utxo` (to block a
        // later deposit) while keeping the request with `executed == true`. That membership
        // must NOT open the permissionless reject path, otherwise anyone could cancel an
        // in-flight refund — so only treat the UTXO as "already deposited" when the request
        // was not executed by us, i.e. a real `verify_deposit` finalized it.
        let executed = self
            .data()
            .refund_requests
            .get(&utxo_storage_key)
            .map(|r| RefundRequest::from(r).executed)
            .unwrap_or(false);
        let is_already_deposited = !executed
            && self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key);
        require!(
            is_privileged || is_already_deposited,
            "Only DAO/Operator can reject, or UTXO must be already verified via deposit"
        );
        self.internal_reject_refund(utxo_storage_key);
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L187-196)
```rust
    pub(crate) fn internal_reject_refund(&mut self, utxo_storage_key: String) {
        require!(
            self.data_mut()
                .refund_requests
                .remove(&utxo_storage_key)
                .is_some(),
            "Refund request not found"
        );
        Event::RefundRejected { utxo_storage_key }.emit();
    }
```
