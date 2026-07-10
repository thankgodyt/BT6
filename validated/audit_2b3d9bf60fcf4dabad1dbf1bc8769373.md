### Title
`reject_refund` Missing Pause Guard Allows State Mutation When Contract Is Paused - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary
`reject_refund` is the only state-mutating function in the refund API that lacks the `#[pause(except(roles(Role::DAO)))]` guard. Every sibling function in the same `impl` block — `request_refund`, `execute_refund`, `verify_refund_finalize`, and `remove_refund_pending_tx_id` — carries the pause check. Because `reject_refund` omits it, any unprivileged caller can invoke it and permanently delete a pending `RefundRequest` entry even while the contract is paused.

### Finding Description
In `contracts/satoshi-bridge/src/api/bridge.rs`, the refund API `impl` block (lines 480–627) exposes five public functions. Four of them carry `#[pause(except(roles(Role::DAO)))]`:

- `request_refund` — `#[pause]` present [1](#0-0) 
- `execute_refund` — `#[pause]` present [2](#0-1) 
- `verify_refund_finalize` — `#[pause]` present [3](#0-2) 
- `remove_refund_pending_tx_id` — `#[pause]` present [4](#0-3) 

`reject_refund` carries **no** `#[pause]` attribute and no `#[trusted_relayer]` attribute on the function itself: [5](#0-4) 

Its permissionless branch allows any caller to reject a refund request when the UTXO is already present in `verified_deposit_utxo` and the request was not self-executed:

```rust
let is_already_deposited = !executed
    && self.data().verified_deposit_utxo.contains(&utxo_storage_key);
require!(
    is_privileged || is_already_deposited,
    "Only DAO/Operator can reject, or UTXO must be already verified via deposit"
);
self.internal_reject_refund(utxo_storage_key);
``` [6](#0-5) 

`internal_reject_refund` permanently removes the `RefundRequest` from storage and emits a `RefundRejected` event with no refund of the attached NEAR storage deposit: [7](#0-6) 

The storage deposit paid by the user at `request_refund` time is explicitly documented as non-refundable (it covers storage and acts as an anti-spam fee). [8](#0-7) 

### Impact Explanation
When the contract is paused (e.g., during an active security incident), an unprivileged attacker can call `reject_refund` for any UTXO that is already in `verified_deposit_utxo` with a non-executed refund request. This permanently deletes the `RefundRequest` entry and causes the user to forfeit the NEAR storage deposit they attached to `request_refund`. No BTC or nBTC is directly stolen, but the bridge's pause invariant — that all state-mutating operations halt for non-DAO callers — is broken for this function. This maps to the **Low** allowed impact: publicly reachable invariant-violation in a production bridge path without direct theft.

### Likelihood Explanation
The condition is reachable by any NEAR account with no special role. The only prerequisite is that a `RefundRequest` exists for a UTXO that was also finalized via `verify_deposit`. This is a realistic race condition (user submits a refund request before the relayer's deposit verification lands). The attacker needs only to observe the on-chain state and call `reject_refund` while the contract is paused.

### Recommendation
Add `#[pause(except(roles(Role::DAO)))]` to `reject_refund`, consistent with every other state-mutating function in the refund API:

```rust
#[pause(except(roles(Role::DAO)))]
pub fn reject_refund(&mut self, utxo_storage_key: String) {
    ...
}
```

### Proof of Concept
1. User sends BTC to a bridge deposit address derived from a `DepositMsg` with `refund_address` set.
2. Relayer calls `verify_deposit` → `verify_deposit_callback` mints nBTC → UTXO key inserted into `verified_deposit_utxo`. [9](#0-8) 
3. User (unaware the deposit landed) calls `request_refund` with the same UTXO, paying the required NEAR storage deposit. A `RefundRequest` with `executed = false` is stored. [10](#0-9) 
4. A security incident triggers a pause: `pa_pause_feature("ALL")` is called by the PauseManager. All sibling refund functions now revert for non-DAO callers.
5. Attacker (any NEAR account) calls `reject_refund(utxo_storage_key)`. Because `reject_refund` has no `#[pause]` guard, the call proceeds. `is_already_deposited` evaluates to `true` (`executed == false` and UTXO is in `verified_deposit_utxo`). [11](#0-10) 
6. `internal_reject_refund` removes the `RefundRequest` from storage and emits `RefundRejected`. The user's NEAR storage deposit is permanently lost. [7](#0-6) 
7. After the pause is lifted, the user's refund request is gone and cannot be re-submitted for the same UTXO (it is already in `verified_deposit_utxo`, so `request_refund_callback` would reject it). [12](#0-11)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L26-47)
```rust
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    #[deprecated(note = "use verify_deposit_v2")]
    pub fn verify_deposit(
        &mut self,
        deposit_msg: DepositMsg,
        tx_bytes: Vec<u8>,
        vout: usize,
        tx_block_blockhash: String,
        tx_index: u64,
        merkle_proof: Vec<String>,
    ) -> Promise {
        self.internal_verify_deposit_entry(
            deposit_msg,
            tx_bytes,
            vout,
            tx_block_blockhash,
            tx_index,
            merkle_proof,
            None,
        )
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L488-490)
```rust
    ///
    /// Requires an attached deposit of at least `required_balance_for_request_refund()`.
    /// The deposit is NOT refunded — it covers request storage and acts as an anti-spam fee.
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L508-535)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn request_refund(
        &mut self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
        gas_fee: Option<U128>,
    ) -> Promise {
        if gas_fee.is_some() {
            let caller = env::predecessor_account_id();
            require!(
                self.acl_has_role(Role::DAO.into(), caller.clone())
                    || self.acl_has_role(Role::Operator.into(), caller),
                "Only DAO or Operator can specify custom gas_fee"
            );
        }
        self.internal_request_refund(
            deposit_msg,
            refund_address,
            tx_bytes,
            vout,
            proof,
            gas_fee.map(|v| v.0),
        )
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L544-568)
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
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L580-582)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn execute_refund(
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L602-604)
```rust
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn verify_refund_finalize(&mut self, tx_id: String, proof: TxInclusionProof) -> Promise {
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L622-624)
```rust
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn remove_refund_pending_tx_id(&mut self, tx_id: String) {
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

**File:** contracts/satoshi-bridge/src/refund.rs (L534-541)
```rust
        // Double-check not finalized (could have been verified between request and callback)
        require!(
            !self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key),
            "UTXO already verified via deposit"
        );
```
