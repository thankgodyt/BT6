### Title
Incomplete State Cleanup in `internal_clear_invalid_pending_verify_rbf` Leaves Stale Entry in Account's `btc_pending_verify_list` - (File: contracts/satoshi-bridge/src/btc_pending_info.rs)

---

### Summary

`internal_clear_invalid_pending_verify_rbf` removes a stale RBF pending info entry from `btc_pending_infos` but does not remove the corresponding tx ID from the account's `btc_pending_verify_list`. This is a direct analog to the vault registry bug: multiple state collections track the same entity, but only one is cleared on removal, leaving the contract in an inconsistent state.

---

### Finding Description

When an RBF transaction is created, its ID is tracked in two places:
1. `btc_pending_infos` (the main map of all pending infos)
2. The account's `btc_pending_verify_list` (once the RBF tx moves from PendingSign → PendingVerify after MPC signing)

Additionally, `rbf_txs` maps `original_tx_id → HashSet<rbf_tx_id>`.

When the original transaction is verified on-chain (finalized), `rbf_txs.remove(original_tx_id)` is called, removing the entire set. The RBF pending info in `btc_pending_infos` is now orphaned — it still exists but its parent is gone. The cleanup function `internal_clear_invalid_pending_verify_rbf` is provided to remove these orphaned RBF entries:

```rust
// contracts/satoshi-bridge/src/btc_pending_info.rs lines 403-413
pub fn internal_clear_invalid_pending_verify_rbf(&mut self, btc_pending_id: String) {
    let btc_pending_info = self.internal_remove_btc_pending_info(&btc_pending_id);
    btc_pending_info.assert_pending_verify();
    let original_tx_id = btc_pending_info
        .get_original_tx_id()
        .expect("Not rbf transaction");
    require!(
        !self.data().rbf_txs.contains_key(original_tx_id),
        "Not invalid pending verify rbf"
    );
}
```

`internal_remove_btc_pending_info` only removes from `btc_pending_infos`:

```rust
// contracts/satoshi-bridge/src/btc_pending_info.rs lines 395-401
pub fn internal_remove_btc_pending_info(&mut self, btc_pending_id: &String) -> BTCPendingInfo {
    self.data_mut()
        .btc_pending_infos
        .remove(btc_pending_id)
        .expect("BTC pending info not exist")
        .into()
}
```

The account's `btc_pending_verify_list` is never touched. Compare this to the correct cleanup pattern used in `verify_refund_finalize_callback` and `internal_remove_refund_pending_tx_id`, which explicitly remove from both maps:

```rust
// contracts/satoshi-bridge/src/refund.rs lines 488-491
self.internal_remove_btc_pending_info(&tx_id);
self.internal_unwrap_mut_account(&account_id)
    .btc_pending_verify_list
    .remove(&tx_id);
```

```rust
// contracts/satoshi-bridge/src/refund.rs lines 427-430
self.internal_remove_btc_pending_info(&tx_id);
let account = self.internal_unwrap_mut_account(&account_id);
account.btc_pending_sign_ids.remove(&tx_id);
account.btc_pending_verify_list.remove(&tx_id);
```

The public entry point `clear_invalid_pending_verify_rbf` (and its batch variant) has no access control beyond the pause guard, making it callable by any account:

```rust
// contracts/satoshi-bridge/src/api/bridge.rs lines 436-446
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

---

### Impact Explanation

After `clear_invalid_pending_verify_rbf` executes, the account's `btc_pending_verify_list` permanently retains a dangling tx ID that no longer exists in `btc_pending_infos`. This breaks the invariant that every ID in `btc_pending_verify_list` corresponds to a live entry in `btc_pending_infos`. The stale entry:

- Causes incorrect data returned by any view function that reads `btc_pending_verify_list`
- Permanently inflates the account's apparent pending-verify count
- Cannot be cleaned up by the user or operator through any existing interface (there is no function to remove an arbitrary entry from `btc_pending_verify_list` without a corresponding pending info)

This is a **Low** severity finding: a publicly reachable invariant violation and stuck-state in a production bridge path, without direct fund theft.

---

### Likelihood Explanation

This is triggered in the normal RBF flow whenever:
1. A user initiates a withdrawal and an RBF is submitted (user or operator RBF)
2. The original transaction confirms on-chain before the RBF
3. Anyone (including the user themselves) calls `clear_invalid_pending_verify_rbf` to clean up the orphaned RBF pending info

This is an expected operational scenario explicitly documented in the contract comments ("Since there can be many RBFs, removing all RBF pending info at once after verifying the transaction on-chain might not have enough gas. Therefore, the off-chain program uses this interface to perform the cleanup."). Every RBF that loses the race to the original tx will trigger this path.

---

### Recommendation

In `internal_clear_invalid_pending_verify_rbf`, after removing from `btc_pending_infos`, also remove the tx ID from the account's `btc_pending_verify_list`:

```rust
pub fn internal_clear_invalid_pending_verify_rbf(&mut self, btc_pending_id: String) {
    let btc_pending_info = self.internal_remove_btc_pending_info(&btc_pending_id);
    btc_pending_info.assert_pending_verify();
    let original_tx_id = btc_pending_info
        .get_original_tx_id()
        .expect("Not rbf transaction");
    require!(
        !self.data().rbf_txs.contains_key(original_tx_id),
        "Not invalid pending verify rbf"
    );
+   // Remove stale entry from account's verify list
+   self.internal_unwrap_mut_account(&btc_pending_info.account_id)
+       .btc_pending_verify_list
+       .remove(&btc_pending_id);
}
```

---

### Proof of Concept

1. User `alice` initiates a withdrawal → `btc_pending_infos["orig_id"]` created, `rbf_txs["orig_id"] = {}`
2. User submits an RBF → `btc_pending_infos["rbf_id"]` created, `rbf_txs["orig_id"] = {"rbf_id"}`, after MPC signing `alice.btc_pending_verify_list = {"rbf_id"}`
3. Original tx confirms on-chain → `verify_withdraw_callback` runs: `rbf_txs.remove("orig_id")`, `btc_pending_infos.remove("orig_id")`, `alice.btc_pending_verify_list.remove("orig_id")`
4. Anyone calls `clear_invalid_pending_verify_rbf("rbf_id")` → `btc_pending_infos.remove("rbf_id")` succeeds
5. **Result**: `btc_pending_infos` no longer contains `"rbf_id"`, but `alice.btc_pending_verify_list` still contains `"rbf_id"` — a permanently dangling reference with no cleanup path [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L395-401)
```rust
    pub fn internal_remove_btc_pending_info(&mut self, btc_pending_id: &String) -> BTCPendingInfo {
        self.data_mut()
            .btc_pending_infos
            .remove(btc_pending_id)
            .expect("BTC pending info not exist")
            .into()
    }
```

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L403-413)
```rust
    pub fn internal_clear_invalid_pending_verify_rbf(&mut self, btc_pending_id: String) {
        let btc_pending_info = self.internal_remove_btc_pending_info(&btc_pending_id);
        btc_pending_info.assert_pending_verify();
        let original_tx_id = btc_pending_info
            .get_original_tx_id()
            .expect("Not rbf transaction");
        require!(
            !self.data().rbf_txs.contains_key(original_tx_id),
            "Not invalid pending verify rbf"
        );
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L436-446)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L426-431)
```rust
        let account_id = btc_pending_info.account_id.clone();
        self.internal_remove_btc_pending_info(&tx_id);
        let account = self.internal_unwrap_mut_account(&account_id);
        account.btc_pending_sign_ids.remove(&tx_id);
        account.btc_pending_verify_list.remove(&tx_id);
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L487-492)
```rust
        // Clean up: remove pending info
        self.internal_remove_btc_pending_info(&tx_id);
        self.internal_unwrap_mut_account(&account_id)
            .btc_pending_verify_list
            .remove(&tx_id);

```
