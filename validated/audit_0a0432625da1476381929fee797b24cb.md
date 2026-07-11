### Title
Missing Pause Guard on `reject_refund` Allows Execution During Paused State - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary

The `reject_refund` function in the satoshi-bridge contract is the only publicly callable, state-mutating function in `bridge.rs` that lacks the `#[pause(except(roles(Role::DAO)))]` decorator. Every other state-mutating function in the same file carries this guard. As a result, any unprivileged NEAR account can invoke `reject_refund` and permanently delete a refund request from contract storage while the contract is in a paused state.

### Finding Description

The satoshi-bridge contract uses the `near-plugins` `Pausable` trait and applies `#[pause(except(roles(Role::DAO)))]` to every public, state-mutating function in `bridge.rs` — `verify_deposit`, `verify_deposit_v2`, `safe_verify_deposit`, `verify_withdraw`, `verify_withdraw_v2`, `withdraw_rbf`, `request_refund`, `execute_refund`, `verify_refund_finalize`, `claim_lost_found`, and all UTXO-management variants. [1](#0-0) 

The single exception is `reject_refund` at line 544, which carries no `#[pause]` attribute at all: [2](#0-1) 

The function has two caller paths:

1. **Privileged path** — DAO or Operator can reject any request.
2. **Permissionless path** — any account can reject a request when `is_already_deposited` is true (the UTXO is in `verified_deposit_utxo` and the request was not executed by the bridge itself).

`internal_reject_refund` permanently removes the entry from `refund_requests` storage: [3](#0-2) 

The contract is declared `Pausable` and all other entry points respect the pause: [4](#0-3) 

### Impact Explanation

When the contract is paused (e.g., in response to a security incident), all deposit, withdrawal, and refund-execution paths are frozen. However, `reject_refund` remains callable. Via the permissionless path, any unprivileged account can permanently delete a refund request whose UTXO was already recorded in `verified_deposit_utxo` before the pause. This bypasses the invariant that a pause freezes all state mutations, and it destroys on-chain state (the refund record) that the user paid a non-refundable storage deposit to create. Additionally, the Operator role — which is not listed in the `except(roles(...))` clause of any other paused function — can call `reject_refund` during a pause to reject any pending refund request, including ones that are still executable, while all other Operator-accessible functions are correctly blocked.

This matches: **Low — Publicly reachable invariant-violation in production bridge/token paths without direct theft.**

### Likelihood Explanation

The permissionless path is reachable by any NEAR account whenever a UTXO has been verified via `verify_deposit` and a refund request for the same UTXO still exists in storage. This is a normal race-condition state the protocol explicitly anticipates (see the `is_already_deposited` guard logic). The pause state is an operational reality (the contract has a `PauseManager` role and tests exercise it). No special privileges or leaked keys are required for the permissionless path.

### Recommendation

Add `#[pause(except(roles(Role::DAO)))]` to `reject_refund`, consistent with every other state-mutating function in the same `impl` block:

```rust
#[pause(except(roles(Role::DAO)))]
pub fn reject_refund(&mut self, utxo_storage_key: String) {
    ...
}
```

If Operator should retain the ability to reject refunds during a pause, add `Role::Operator` to the `except` list explicitly and document the intent.

### Proof of Concept

1. The bridge is operating normally. Alice submits `request_refund` for UTXO `txid@0`; the relayer also calls `verify_deposit` for the same UTXO, minting nBTC and inserting `txid@0` into `verified_deposit_utxo`. The refund request remains in storage with `executed = false`.
2. A security incident is detected; the PauseManager calls `pa_pause_feature("ALL")`. All functions decorated with `#[pause]` now revert with "Method is paused".
3. Bob (any unprivileged NEAR account) calls `reject_refund("txid@0")`. Because `is_already_deposited` is `true` (`!executed && verified_deposit_utxo.contains("txid@0")`), the `require!` passes. `internal_reject_refund` removes the refund request from storage and emits `RefundRejected`. The call succeeds despite the contract being fully paused.
4. Alice's refund record is permanently gone. No other paused function could have been called by Bob during this window. [5](#0-4) [3](#0-2)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L507-510)
```rust
    #[allow(clippy::too_many_arguments)]
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn request_refund(
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

**File:** contracts/satoshi-bridge/src/lib.rs (L160-163)
```rust
#[near(contract_state)]
#[derive(Pausable, Upgradable, PanicOnDefault)]
#[access_control(role_type(Role))]
#[pausable(pause_roles(Role::PauseManager), unpause_roles(Role::UnpauseManager))]
```
