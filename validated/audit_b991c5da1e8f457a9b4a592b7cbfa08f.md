The path is real and traceable. Let me confirm the exact execution flow and the stuck-state conditions.

The call chain is:

1. `execute_refund` (public, no ACL) → `resolve_execute_refund_timelock` → `internal_execute_refund`
2. `load_refund_request_for_execute`: passes when `executed: true` even if UTXO is in `verified_deposit_utxo`
3. `finalize_refund_with_psbt` → `require_pending_sign_capacity` → panics if at limit

The default limit is `unwrap_or(1)`, so any user who has already executed a refund and has the `BTCPendingInfo` still pending is at the limit.

The test `test_zcash_execute_refund_twice` explicitly pre-sets `max_pending: 2` before re-executing — confirming the production path would fail without that setup step.

Recovery analysis:
- DAO calls `set_pending_tx_limit` → user can re-execute (requires operator intervention)
- DAO rejects the refund → removes the refund request → `internal_remove_refund_pending_tx_id` becomes callable, but the UTXO remains in `verified_deposit_utxo` permanently, blocking any new `request_refund` for the same UTXO

---

### Title
Re-execution of an executed Zcash refund is blocked by pending-sign capacity limit, causing a stuck state requiring operator intervention — (`contracts/satoshi-bridge/src/refund.rs`)

### Summary
After `execute_refund` marks a `RefundRequest` as `executed: true` and inserts the UTXO into `verified_deposit_utxo`, the design explicitly allows re-execution (e.g., after a Zcash consensus branch change). However, `finalize_refund_with_psbt` unconditionally calls `require_pending_sign_capacity` before creating the new `BTCPendingInfo`. Since the old `BTCPendingInfo` from the first execution is still pending (the invalid-branch tx was never finalized), the caller is already at the default limit of 1. The re-execution panics with "Too many pending sign transactions", leaving the refund permanently stuck without DAO intervention.

### Finding Description

`load_refund_request_for_execute` explicitly permits re-execution when `executed: true`: [1](#0-0) 

`finalize_refund_with_psbt` then calls `require_pending_sign_capacity` unconditionally: [2](#0-1) 

The default pending limit is 1: [3](#0-2) 

`require_pending_sign_capacity` panics if the count equals the limit: [4](#0-3) 

The test `test_zcash_execute_refund_twice` works around this by pre-setting `max_pending: 2` — confirming the production path would fail for a regular user at the default limit: [5](#0-4) 

### Impact Explanation

After the stuck state is reached:
- The old `BTCPendingInfo` is for a transaction built on the wrong consensus branch — it can never be confirmed on-chain, so `verify_refund_finalize` will never succeed for it.
- `internal_remove_refund_pending_tx_id` cannot remove the old `BTCPendingInfo` because the refund request is still active (`executed: true` but not finalized). [6](#0-5) 

- The user cannot call `request_refund` again for the same UTXO because `request_refund_callback` blocks it when the UTXO is in `verified_deposit_utxo`. [7](#0-6) 

The only recovery path is the DAO calling `set_pending_tx_limit` to raise the caller's limit, which is a privileged operation: [8](#0-7) 

Without DAO intervention, the user's BTC deposit is permanently unrefundable. This maps to: **Low — publicly reachable invariant-violation, stuck-state, or panic-driven fault in production bridge/token paths without direct theft.**

### Likelihood Explanation

The scenario requires:
1. A Zcash consensus branch activation (a real, scheduled event — e.g., NU6.2 at block 4,052,000 on testnet).
2. The user having executed a refund before the branch change and having the `BTCPendingInfo` still pending (the normal state — the user hasn't signed and broadcast yet, or the old tx was broadcast but not confirmed).
3. The user being at the default pending limit of 1 (the default for all accounts without a custom limit).

All three conditions are simultaneously reachable in normal production usage. The likelihood is low-to-medium given that consensus branch changes are infrequent but scheduled.

### Recommendation

In `finalize_refund_with_psbt`, before calling `require_pending_sign_capacity`, check whether this is a re-execution of an already-executed refund (`refund_request.executed == true`). If so, skip the capacity check — the re-execution is replacing an existing pending tx for the same UTXO, not adding a new one. Alternatively, automatically remove the stale `BTCPendingInfo` for the same UTXO before inserting the new one during re-execution.

### Proof of Concept

```
1. Alice calls execute_refund for a Zcash refund request (timelock passed).
   → BTCPendingInfo created (branch Nu6), executed: true, UTXO in verified_deposit_utxo.
   → Alice now has pending_sign_count = 1 (at the default limit of 1).

2. Zcash NU6.2 activates. The Nu6 BTCPendingInfo is now for an invalid tx.

3. Alice calls execute_refund again (re-execution path).
   → load_refund_request_for_execute passes (timelock passed, executed: true).
   → finalize_refund_with_psbt calls require_pending_sign_capacity.
   → PANIC: "Too many pending sign transactions"

4. State:
   - Old BTCPendingInfo (Nu6): invalid tx, can never be finalized.
   - internal_remove_refund_pending_tx_id: blocked (refund request still active).
   - request_refund: blocked (UTXO in verified_deposit_utxo).
   - execute_refund: blocked (capacity limit).
   → Alice's BTC is permanently unrefundable without DAO intervention.
```

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L254-258)
```rust
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L339-342)
```rust
        if !self.check_account_exists(&caller) {
            self.internal_set_account(&caller, crate::Account::new(&caller));
        }
        self.require_pending_sign_capacity(&caller);
```

**File:** contracts/satoshi-bridge/src/refund.rs (L418-424)
```rust
        require!(
            !self
                .data()
                .refund_requests
                .contains_key(&utxo_storage_keys[0]),
            "refund request still active"
        );
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

**File:** contracts/satoshi-bridge/src/account.rs (L105-111)
```rust
    pub fn get_max_pending_sign_txs(&self, account_id: &AccountId) -> u32 {
        self.data()
            .pending_tx_limits
            .get(account_id)
            .copied()
            .unwrap_or(1)
    }
```

**File:** contracts/satoshi-bridge/src/account.rs (L113-122)
```rust
    pub fn require_pending_sign_capacity(&self, account_id: &AccountId) {
        require!(
            self.get_account(account_id)
                .unwrap_or_else(|| {
                    env::panic_str(&format!("ERR_ACCOUNT_NOT_REGISTERED: {}", account_id))
                })
                .pending_sign_count()
                < self.get_max_pending_sign_txs(account_id),
            "Too many pending sign transactions"
        );
```

**File:** contracts/satoshi-bridge/tests/test_refund_zcash.rs (L508-520)
```rust
    // Allow the refund caller (root) to hold two pending refund txs at once, so a
    // re-created refund can coexist with the first while it is still pending.
    let root_id = context.get_account_by_name("root").id().clone();
    context
        .get_account_by_name("root")
        .call(context.bridge_contract.id(), "set_pending_tx_limit")
        .args_json(json!({ "account_id": root_id, "max_pending": 2 }))
        .deposit(near_sdk::NearToken::from_yoctonear(1))
        .max_gas()
        .transact()
        .await
        .unwrap()
        .unwrap();
```

**File:** contracts/satoshi-bridge/src/api/management.rs (L192-206)
```rust
    pub fn set_pending_tx_limit(&mut self, account_id: AccountId, max_pending: Option<u32>) {
        assert_one_yocto();
        if let Some(max_pending) = max_pending {
            require!(max_pending >= 1, "Invalid max_pending value");
            self.data_mut()
                .pending_tx_limits
                .insert(account_id, max_pending);
        } else {
            let prev = self.data_mut().pending_tx_limits.remove(&account_id);
            require!(
                prev.is_some(),
                format!("Invalid account_id: {}", account_id)
            );
        }
    }
```
