### Title
Missing Access Control on `clear_invalid_pending_verify_rbf` / `batch_clear_invalid_pending_verify_rbf` Allows Any Caller to Corrupt Account Pending-State - (File: contracts/satoshi-bridge/src/api/bridge.rs)

---

### Summary

`clear_invalid_pending_verify_rbf` and `batch_clear_invalid_pending_verify_rbf` carry only a `#[pause]` guard and no role or relayer restriction. Any unprivileged NEAR account can invoke them. The underlying implementation removes the entry from `btc_pending_infos` but never removes it from the owning account's `btc_pending_verify_list`, leaving a dangling reference that permanently corrupts the account's pending-operation state.

---

### Finding Description

The two public functions are declared as:

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
``` [1](#0-0) 

Every other state-mutating function in the same `impl` block that is intended for operator/relayer use carries `#[access_control_any(roles(Role::DAO, Role::Operator))]` or `#[trusted_relayer]`. These two functions carry neither. The code comment explicitly states the intended caller: *"the off-chain program uses this interface to perform the cleanup"* — yet no enforcement exists. [2](#0-1) 

The internal implementation is:

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
``` [3](#0-2) 

`internal_remove_btc_pending_info` removes the entry from the `btc_pending_infos` map. [4](#0-3) 

However, unlike every other removal path in the codebase (e.g. `internal_remove_refund_pending_tx_id` which explicitly calls `account.btc_pending_sign_ids.remove` and `account.btc_pending_verify_list.remove`), `internal_clear_invalid_pending_verify_rbf` **never touches the owning account's `btc_pending_verify_list`**. [5](#0-4) 

The result is a dangling key in `btc_pending_verify_list` that points to a now-deleted `btc_pending_infos` entry.

---

### Impact Explanation

An attacker who identifies any RBF pending-verify entry whose original transaction has already been removed from `rbf_txs` (i.e., the original withdrawal was verified on-chain) can call `clear_invalid_pending_verify_rbf` with that ID. This:

1. Deletes the `btc_pending_infos` record.
2. Leaves a stale key in the victim account's `btc_pending_verify_list`.

Any subsequent bridge operation that iterates or counts `btc_pending_verify_list` entries and attempts to resolve them against `btc_pending_infos` will encounter a missing entry. Depending on how `require_pending_sign_capacity` and related helpers consume this list, the victim account can be permanently stuck — unable to initiate new withdrawals or refunds — until an operator manually repairs state. This matches the **Medium** impact class: *attacker-triggered temporary/permanent locking of bridged funds* and *stuck bridge state requiring operator intervention*.

---

### Likelihood Explanation

The function is unconditionally reachable by any NEAR account when the contract is not paused. No deposit, no token balance, and no special role is required. An attacker only needs to observe on-chain state (public) to identify eligible `btc_pending_verify_id` values. Likelihood is **Medium**.

---

### Recommendation

Add `#[access_control_any(roles(Role::DAO, Role::Operator))]` (and `assert_one_yocto()`) to both `clear_invalid_pending_verify_rbf` and `batch_clear_invalid_pending_verify_rbf`, consistent with every other operator-intended function in the same `impl` block.

Additionally, `internal_clear_invalid_pending_verify_rbf` must be fixed to also remove the key from the owning account's `btc_pending_verify_list`, mirroring the cleanup pattern used in `internal_remove_refund_pending_tx_id`.

---

### Proof of Concept

1. Alice initiates a withdrawal; the bridge creates `btc_pending_infos["withdraw-rbf-tx-1"]` in `PendingVerify` state, and `alice.btc_pending_verify_list` contains `"withdraw-rbf-tx-1"`.
2. The original withdrawal tx is verified on-chain; `rbf_txs` entry for the original tx is removed. `"withdraw-rbf-tx-1"` is now an invalid RBF candidate.
3. Attacker (any NEAR account) calls `clear_invalid_pending_verify_rbf("withdraw-rbf-tx-1")`.
4. `internal_remove_btc_pending_info` deletes `btc_pending_infos["withdraw-rbf-tx-1"]`.
5. `alice.btc_pending_verify_list` still contains `"withdraw-rbf-tx-1"` — a dangling reference.
6. Alice's account now has a permanently stale pending-verify entry. Any bridge path that resolves this key against `btc_pending_infos` will panic or produce incorrect capacity counts, blocking Alice from future bridge operations without operator intervention.

### Citations

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

**File:** contracts/satoshi-bridge/src/refund.rs (L426-431)
```rust
        let account_id = btc_pending_info.account_id.clone();
        self.internal_remove_btc_pending_info(&tx_id);
        let account = self.internal_unwrap_mut_account(&account_id);
        account.btc_pending_sign_ids.remove(&tx_id);
        account.btc_pending_verify_list.remove(&tx_id);
    }
```
