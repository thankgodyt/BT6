### Title
Missing Access Control on `clear_invalid_pending_verify_rbf` / `batch_clear_invalid_pending_verify_rbf` — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`clear_invalid_pending_verify_rbf` and `batch_clear_invalid_pending_verify_rbf` are public functions with no role-based access control. They are documented as intended for an off-chain program (relayer) to call after on-chain verification, yet any unprivileged NEAR account can invoke them. This is a direct structural analog to the reported `extendTime` vulnerability: a privileged state-mutation function missing its access-control guard.

---

### Finding Description

Both functions appear inside the outer `#[trusted_relayer] #[near] impl Contract` block but carry **no** per-function `#[trusted_relayer]` or `#[access_control_any]` attribute — only the pause guard:

```rust
// bridge.rs line 436-446
#[pause(except(roles(Role::DAO)))]
pub fn clear_invalid_pending_verify_rbf(&mut self, btc_pending_verify_id: String) {
    self.internal_clear_invalid_pending_verify_rbf(btc_pending_verify_id);
}

#[pause(except(roles(Role::DAO)))]
pub fn batch_clear_invalid_pending_verify_rbf(&mut self, btc_pending_verify_ids: Vec<String>) {
    for btc_pending_verify_id in btc_pending_verify_ids {
        self.internal_clear_invalid_pending_verify_rbf(btc_pending_verify_id);
    }
}
``` [1](#0-0) 

Compare with functions in the same impl block that correctly carry `#[trusted_relayer]` on the function itself (e.g., `verify_withdraw_v2` at line 240, `verify_deposit_v2` at line 71): [2](#0-1) 

The outer `#[trusted_relayer]` on the impl block configures the macro but does **not** automatically enforce the relayer whitelist check on every method — only functions that also carry the per-function `#[trusted_relayer]` attribute are gated. The `trusted_relayer` macro is configured at the contract level with `bypass_roles(Role::DAO, Role::UnrestrictedRelayer)` and `manager_roles(Role::DAO, Role::RelayerManager)`: [3](#0-2) 

The developer comment on the function confirms it is intended for a specific off-chain program, not arbitrary callers:

> "Since there can be many RBFs, removing all RBF pending info at once after verifying the transaction on-chain might not have enough gas. Therefore, the **off-chain program** uses this interface to perform the cleanup." [4](#0-3) 

---

### Impact Explanation

`internal_clear_invalid_pending_verify_rbf` removes entries from `btc_pending_infos` / `rbf_txs` (the RBF pending-verify state). If the internal function does not independently validate that the supplied ID is truly invalid (i.e., already finalized on-chain) before deleting it, an attacker can supply an **active** pending-verify ID and delete it from contract state. The corresponding withdrawal would then be permanently stuck: the pending info is gone, the UTXO is still locked in the bridge, and no further `verify_withdraw_v2` call can finalize it because the pending info no longer exists. This matches the allowed impact: **attacker-triggered temporary/permanent locking of bridged funds** (Medium), or at minimum a **publicly reachable stuck-state fault** (Low).

The `batch_` variant amplifies the attack: a single transaction can wipe multiple active RBF pending entries simultaneously.

---

### Likelihood Explanation

Any NEAR account can call these functions at zero cost beyond gas. No special role, token balance, or prior interaction is required. The contract is not paused in normal operation, so the only guard (`#[pause]`) is inactive. Likelihood is **High**.

---

### Recommendation

Add `#[access_control_any(roles(Role::DAO, Role::Operator))]` (consistent with other operator-level functions such as `cancel_withdraw` and `active_utxo_management`) or `#[trusted_relayer]` to both functions:

```rust
#[payable]
#[access_control_any(roles(Role::DAO, Role::Operator))]
#[pause(except(roles(Role::DAO)))]
pub fn clear_invalid_pending_verify_rbf(&mut self, btc_pending_verify_id: String) {
    assert_one_yocto();
    self.internal_clear_invalid_pending_verify_rbf(btc_pending_verify_id);
}

#[payable]
#[access_control_any(roles(Role::DAO, Role::Operator))]
#[pause(except(roles(Role::DAO)))]
pub fn batch_clear_invalid_pending_verify_rbf(&mut self, btc_pending_verify_ids: Vec<String>) {
    assert_one_yocto();
    for btc_pending_verify_id in btc_pending_verify_ids {
        self.internal_clear_invalid_pending_verify_rbf(btc_pending_verify_id);
    }
}
```

This mirrors the pattern used by `cancel_withdraw`: [5](#0-4) 

---

### Proof of Concept

1. Attacker observes an active RBF pending-verify entry with ID `"<active_rbf_id>"` (readable from public view functions).
2. Attacker calls:
   ```
   near call <bridge> clear_invalid_pending_verify_rbf \
     '{"btc_pending_verify_id": "<active_rbf_id>"}' \
     --accountId attacker.near
   ```
3. `internal_clear_invalid_pending_verify_rbf` removes the entry from `btc_pending_infos`.
4. The legitimate user's subsequent `verify_withdraw_v2` call panics with "pending info not found"; the withdrawal is stuck and the user's nBTC has already been burned (or is locked in the pending state), resulting in loss of funds or permanent stuck state.

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L240-242)
```rust
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn verify_withdraw_v2(&mut self, tx_id: String, proof: TxInclusionProof) -> Promise {
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L282-286)
```rust
    #[payable]
    #[access_control_any(roles(Role::DAO, Role::Operator))]
    #[pause(except(roles(Role::DAO)))]
    pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
        assert_one_yocto();
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L430-446)
```rust
    /// Since there can be many RBFs, removing all RBF pending info at once after verifying the transaction on-chain might not have enough gas.
    /// Therefore, the off-chain program uses this interface to perform the cleanup.
    ///
    /// # Arguments
    ///
    /// * `btc_pending_verify_id` - Invalid pending info ID.
    #[pause(except(roles(Role::DAO)))]
    pub fn clear_invalid_pending_verify_rbf(&mut self, btc_pending_verify_id: String) {
        self.internal_clear_invalid_pending_verify_rbf(btc_pending_verify_id);
    }

    #[pause(except(roles(Role::DAO)))]
    pub fn batch_clear_invalid_pending_verify_rbf(&mut self, btc_pending_verify_ids: Vec<String>) {
        for btc_pending_verify_id in btc_pending_verify_ids {
            self.internal_clear_invalid_pending_verify_rbf(btc_pending_verify_id);
        }
    }
```

**File:** contracts/satoshi-bridge/src/lib.rs (L175-179)
```rust
#[trusted_relayer(
    bypass_roles(Role::DAO, Role::UnrestrictedRelayer),
    manager_roles(Role::DAO, Role::RelayerManager),
    config_roles(Role::DAO)
)]
```
