### Title
Publicly Callable `clear_invalid_pending_verify_rbf` Leaves Stale Account State, Creating Invariant Violation - (File: `contracts/satoshi-bridge/src/btc_pending_info.rs`, `contracts/satoshi-bridge/src/api/bridge.rs`)

### Summary
The `clear_invalid_pending_verify_rbf` (and `batch_clear_invalid_pending_verify_rbf`) functions are callable by any unprivileged NEAR account with no access control. When successfully executed, they remove an entry from `btc_pending_infos` but fail to remove the corresponding entry from the owning account's `btc_pending_verify_list`, leaving the account in a permanently inconsistent state. This is the direct analog of the "overly broad permissions" class: an operation that should be restricted to trusted relayers/operators is instead open to the public, and the consequence is a reachable invariant violation in production bridge state.

### Finding Description
`clear_invalid_pending_verify_rbf` is decorated only with `#[pause(except(roles(Role::DAO)))]` — no `#[trusted_relayer]`, no `#[access_control_any]`. Any NEAR account can call it. [1](#0-0) 

The internal implementation calls `internal_remove_btc_pending_info`, which removes the entry exclusively from `data.btc_pending_infos`: [2](#0-1) 

It does **not** remove the corresponding ID from `account.btc_pending_verify_list` or `account.btc_pending_sign_ids`. The full `internal_clear_invalid_pending_verify_rbf` body confirms this omission: [3](#0-2) 

Contrast this with `internal_remove_refund_pending_tx_id`, which correctly cleans up both the pending info map **and** the account's tracking sets: [4](#0-3) 

After a successful call to `clear_invalid_pending_verify_rbf`, the victim account holds a dangling reference in `btc_pending_verify_list` pointing to a now-deleted `BTCPendingInfo`. Any subsequent code path that iterates or dereferences entries in `btc_pending_verify_list` for that account will encounter missing state.

### Impact Explanation
The account is left in a permanently broken state: `btc_pending_verify_list` contains an ID for which no `BTCPendingInfo` exists. Any bridge operation that walks or dereferences `btc_pending_verify_list` for the affected account will either panic or produce incorrect results. This is a publicly reachable invariant violation in a production bridge path — the account's internal state is corrupted without any privileged access required.

**Impact class:** Low — publicly reachable invariant-violation / stuck-state in production bridge paths without direct fund theft.

### Likelihood Explanation
Any NEAR account can call `clear_invalid_pending_verify_rbf` at any time. The only precondition is that a valid RBF pending-verify entry exists whose original transaction is no longer tracked in `rbf_txs` (i.e., the original was already finalized). This is a normal operational state during active bridge usage. No special privileges, leaked keys, or third-party compromise are required.

### Recommendation
Either:
1. Restrict `clear_invalid_pending_verify_rbf` to trusted relayers or operators using `#[trusted_relayer]` or `#[access_control_any(roles(Role::DAO, Role::Operator))]`, consistent with the comment that "the off-chain program uses this interface"; **and**
2. Add the missing account cleanup inside `internal_clear_invalid_pending_verify_rbf`, mirroring the pattern in `internal_remove_refund_pending_tx_id`:
   ```rust
   let account_id = btc_pending_info.account_id.clone();
   self.internal_remove_btc_pending_info(&btc_pending_id);
   let account = self.internal_unwrap_mut_account(&account_id);
   account.btc_pending_sign_ids.remove(&btc_pending_id);
   account.btc_pending_verify_list.remove(&btc_pending_id);
   ```

### Proof of Concept
1. Alice initiates a withdrawal; an RBF is created and moves to `PendingVerify` stage. The original tx is later finalized, removing its entry from `rbf_txs`.
2. Eve (any unprivileged NEAR account) calls `clear_invalid_pending_verify_rbf(alice_rbf_pending_id)`.
3. The function passes all checks and removes the entry from `btc_pending_infos`.
4. Alice's account still holds `alice_rbf_pending_id` in `btc_pending_verify_list`.
5. Any subsequent bridge operation on Alice's account that references `btc_pending_verify_list` encounters a dangling ID, causing a panic or incorrect behavior — Alice's account is stuck.

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L436-439)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn clear_invalid_pending_verify_rbf(&mut self, btc_pending_verify_id: String) {
        self.internal_clear_invalid_pending_verify_rbf(btc_pending_verify_id);
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

**File:** contracts/satoshi-bridge/src/refund.rs (L426-430)
```rust
        let account_id = btc_pending_info.account_id.clone();
        self.internal_remove_btc_pending_info(&tx_id);
        let account = self.internal_unwrap_mut_account(&account_id);
        account.btc_pending_sign_ids.remove(&tx_id);
        account.btc_pending_verify_list.remove(&tx_id);
```
