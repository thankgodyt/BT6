### Title
`reject_refund` Missing Pause Guard Allows Permissionless State Mutation During Emergency Pause — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

Every state-mutating public function in the bridge is decorated with `#[pause(except(roles(Role::DAO)))]` to block execution during an emergency pause — except `reject_refund`. An unprivileged NEAR account can call `reject_refund` at any time, including while the contract is paused, to destroy a victim's pending refund request and permanently forfeit the NEAR storage deposit the victim attached when calling `request_refund`.

---

### Finding Description

The bridge exposes a `reject_refund` function that allows **anyone** to reject a refund request when the target UTXO has already been recorded in `verified_deposit_utxo` (i.e., a `verify_deposit` call finalized the same UTXO before the refund was executed):

```rust
// contracts/satoshi-bridge/src/api/bridge.rs  lines 544-568
pub fn reject_refund(&mut self, utxo_storage_key: String) {
    let caller = env::predecessor_account_id();
    let is_privileged = self.acl_has_role(Role::DAO.into(), caller.clone())
        || self.acl_has_role(Role::Operator.into(), caller);
    let executed = ...;
    let is_already_deposited = !executed
        && self.data().verified_deposit_utxo.contains(&utxo_storage_key);
    require!(
        is_privileged || is_already_deposited,
        "Only DAO/Operator can reject, or UTXO must be already verified via deposit"
    );
    self.internal_reject_refund(utxo_storage_key);
}
``` [1](#0-0) 

Crucially, this function carries **no** `#[pause]` attribute. Compare with every other state-mutating entry point in the same file: [2](#0-1) [3](#0-2) 

`request_refund` (line 509) and `execute_refund` (line 581) both carry `#[pause(except(roles(Role::DAO)))]`, but `reject_refund` between them does not.

`internal_reject_refund` unconditionally removes the request from storage and emits `RefundRejected`: [4](#0-3) 

The NEAR storage deposit the victim attached to `request_refund` (sized to cover up to ~200 KB ≈ 2 NEAR per the inline comment) is **not returned** on rejection — it is consumed as an anti-spam fee: [5](#0-4) 

---

### Impact Explanation

When the bridge is paused (emergency), an attacker can call `reject_refund` for any refund request whose UTXO was already finalized via `verify_deposit`. The victim's refund request is permanently deleted and their attached NEAR deposit (up to ~2 NEAR) is forfeited. Because `verify_deposit` is itself pause-gated, the attacker only needs to wait for a pre-pause deposit finalization to create the exploitable condition, then act during the pause window before the victim can react. This is a publicly reachable invariant violation: the pause mechanism is supposed to freeze all state mutations for non-DAO callers, but `reject_refund` is exempt without justification.

**Allowed impact category**: Low — publicly reachable invariant-violation in a production bridge path without direct BTC/nBTC theft.

---

### Likelihood Explanation

The condition `is_already_deposited == true` (UTXO in `verified_deposit_utxo`, refund request not yet executed) is a normal transient state: a user submits `request_refund` for a UTXO that a relayer subsequently finalizes via `verify_deposit`. This race is explicitly anticipated by the code (the double-check in `request_refund_callback` at line 535). Any pause triggered after such a finalization but before the victim calls `reject_refund` themselves opens the window. The attacker needs no special role or key — only knowledge of the `utxo_storage_key` (a deterministic `{tx_id}@{vout}` string, publicly derivable from on-chain events). [6](#0-5) 

---

### Recommendation

Add `#[pause(except(roles(Role::DAO)))]` to `reject_refund`, consistent with every other state-mutating public function in the contract:

```rust
#[pause(except(roles(Role::DAO)))]
pub fn reject_refund(&mut self, utxo_storage_key: String) {
``` [7](#0-6) 

---

### Proof of Concept

1. User Alice calls `request_refund` for UTXO `abc123@0`, attaching 2 NEAR as the storage deposit. The refund request is stored; `executed = false`.
2. A relayer calls `verify_deposit_v2` for the same UTXO before the pause — nBTC is minted to Alice, and `verified_deposit_utxo` now contains `abc123@0`.
3. The DAO pauses the bridge (emergency). All `#[pause]`-gated functions revert for non-DAO callers.
4. Eve (unprivileged) calls `reject_refund("abc123@0")`. Because `executed == false` and `verified_deposit_utxo.contains("abc123@0")`, `is_already_deposited` is `true`, the `require!` passes, and `internal_reject_refund` removes Alice's refund request.
5. Alice's 2 NEAR anti-spam deposit is permanently lost. She cannot re-submit `request_refund` while the bridge is paused (that function is pause-gated), and the refund request is gone. [8](#0-7)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L508-510)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn request_refund(
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

**File:** contracts/satoshi-bridge/src/refund.rs (L17-26)
```rust
/// Upper bound on the deposit `tx_bytes` accepted by `request_refund`.
///
/// The RefundRequest stores `tx_bytes` verbatim (no truncation — `execute_refund`
/// later decodes them to rebuild the refund tx), so storage grows ~1:1 with tx size:
/// at this cap a request stores ~200 KB ≈ 2 NEAR, which `required_balance_for_request_refund`
/// is sized to cover. The cap also sits safely below the hard gas ceiling: decoding +
/// borsh-storing the tx happens in `request_refund_callback` (only 20 Tgas), which runs
/// out of gas around ~250 KB regardless of the attached deposit. 200 KB is ~1350 signed
/// P2PKH inputs — far above any real deposit (1-2 inputs), incl. large consolidations.
pub(crate) const MAX_REQUEST_REFUND_TX_BYTES: usize = 200_000;
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
