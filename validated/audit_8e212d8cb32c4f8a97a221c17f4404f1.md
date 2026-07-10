The key question is whether `get_pending_id()` produces the same ID on re-execution, and whether the old `BTCPendingInfo` is cleaned up before the new one is inserted. Let me verify the exact PSBT ID derivation and the `execute_refund` public access control.

## Analysis

### Tracing the Re-execution Path

**Step 1 — First `execute_refund` call (succeeds):**

`execute_refund` → `resolve_execute_refund_timelock` → `internal_execute_refund` → `load_refund_request_for_execute` (passes, `executed=false`) → builds PSBT → `finalize_refund_with_psbt`: [1](#0-0) 

This inserts `BTCPendingInfo` into `btc_pending_infos`, inserts `utxo_storage_key` into `verified_deposit_utxo`, and re-saves the request with `executed=true`.

**Step 2 — `btc_pending_id` is deterministic:**

`get_pending_id()` calls `extract_tx().compute_txid()` on the unsigned transaction: [2](#0-1) 

The unsigned tx is built from `outpoint` (deposit txid + vout) and `refund_output` (refund_amount + refund_address script), both of which are fixed fields from the stored `RefundRequest`. Every re-execution of `execute_refund` for the same request produces **the identical `btc_pending_id`**.

**Step 3 — Second `execute_refund` call (panics):**

`load_refund_request_for_execute` explicitly allows re-execution when `executed=true`: [3](#0-2) 

But `finalize_refund_with_psbt` then hits: [4](#0-3) 

Because the old `BTCPendingInfo` (from the first execution) was never removed, `insert(...).is_none()` is `false` → **panic: "pending info already exist"**.

**Step 4 — `remove_refund_pending_tx_id` also blocked:** [5](#0-4) 

The refund request still exists (only removed in `verify_refund_finalize_callback`), so this guard fires too.

**Step 5 — `execute_refund` is publicly callable:**

The function has no individual `#[trusted_relayer]` and no ACL check in its body — only a timelock: [6](#0-5) 

Any unprivileged caller can trigger this after the timelock elapses.

---

### Is the Deadlock Permanent?

**No — it is not permanent.** The DAO/Operator has two escape routes:

1. **`reject_refund`** (DAO/Operator only) removes the refund request from `refund_requests`. After that, `remove_refund_pending_tx_id` succeeds because the guard `!refund_requests.contains_key(...)` passes. [7](#0-6) 

2. If the `BTCPendingInfo` is still in `PendingSign` stage, the relayer can sign and submit the original tx, and `verify_refund_finalize_callback` cleans everything up normally.

The `verified_deposit_utxo` entry persists after `reject_refund`, but that is expected behavior (it prevents double-deposit of the same UTXO).

---

### Verdict

The re-execution panic is a **real, reachable invariant violation** — the design comment explicitly says `execute_refund` must be re-callable after a branch change, but the implementation does not remove the stale `BTCPendingInfo` before inserting a new one. The stuck state is real and publicly triggerable, but it is **not permanent**: operator intervention (`reject_refund` + `remove_refund_pending_tx_id`) breaks it. There is no direct fund theft — the deposit UTXO is temporarily locked until the operator acts.

This matches the **Low** impact tier ("publicly reachable invariant-violation, stuck-state, or panic-driven fault in production bridge/token paths without direct theft"), not the "permanent deadlock" framing in the question.

---

### Title
Re-execution of `execute_refund` panics on deterministic PSBT ID collision, causing stuck refund state — (`contracts/satoshi-bridge/src/refund.rs`)

### Summary
When `execute_refund` is called a second time for a request whose first `BTCPendingInfo` was never cleaned up (refund tx unconfirmed), `finalize_refund_with_psbt` panics at the `is_none()` guard because the PSBT ID is deterministic and the old entry still occupies `btc_pending_infos`. `remove_refund_pending_tx_id` is simultaneously blocked by the still-present refund request. The state requires DAO/Operator intervention to unblock.

### Finding Description
`finalize_refund_with_psbt` inserts a new `BTCPendingInfo` keyed by `btc_pending_id = psbt.get_pending_id()`, which is the Bitcoin txid of the unsigned refund transaction. Because the unsigned tx is built deterministically from the stored `RefundRequest` fields (deposit outpoint + refund amount + refund address), every re-execution of `execute_refund` for the same request produces the same `btc_pending_id`. If the first `BTCPendingInfo` was not cleaned up (i.e., `verify_refund_finalize_callback` was never called), the `insert(...).is_none()` assertion fires. Simultaneously, `remove_refund_pending_tx_id` is blocked by the `!refund_requests.contains_key(...)` guard, since the request is only removed on finalization.

### Impact Explanation
The deposit UTXO is locked in `verified_deposit_utxo`, the stale `BTCPendingInfo` cannot be removed, and `execute_refund` cannot produce a new refund transaction. The user's BTC is temporarily inaccessible until a DAO/Operator calls `reject_refund` followed by `remove_refund_pending_tx_id`. No direct fund theft occurs.

### Likelihood Explanation
Reachable whenever a refund transaction is broadcast but not confirmed (low fees, chain reorg) and `execute_refund` is called again — a scenario the code explicitly intends to support per its own comments. Any unprivileged caller can trigger the second call after the timelock.

### Recommendation
In `finalize_refund_with_psbt`, before inserting the new `BTCPendingInfo`, check whether an entry for `btc_pending_id` already exists and remove it (along with the account's `btc_pending_sign_ids` / `btc_pending_verify_list` entries) when `refund_request.executed == true`. This makes re-execution idempotent and matches the stated design intent.

### Proof of Concept
1. Submit a valid refund request; wait for the timelock.
2. Call `execute_refund` → succeeds; `BTCPendingInfo` created, `executed=true`.
3. Do not confirm the refund tx on-chain (simulate low fees or reorg).
4. Call `execute_refund` again → panics: `"pending info already exist"`.
5. Call `remove_refund_pending_tx_id(btc_pending_id)` → panics: `"refund request still active"`.
6. State: `verified_deposit_utxo` contains the key, `btc_pending_infos` contains the stale entry, `refund_requests` still contains the request — no public call can make progress.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L253-258)
```rust
        // after a consensus branch change.
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L366-401)
```rust
        require!(
            self.data_mut()
                .btc_pending_infos
                .insert(btc_pending_id.clone(), btc_pending_info.into())
                .is_none(),
            "pending info already exist"
        );
        self.internal_unwrap_mut_account(&caller)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());

        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());

        Event::RefundExecuted {
            utxo_storage_key: utxo_storage_key.clone(),
            amount: refund_request.amount.into(),
            refund_address,
        }
        .emit();

        Event::GenerateBtcPendingInfo {
            account_id: &caller,
            btc_pending_id: &btc_pending_id,
        }
        .emit();

        // Keep the request (so `execute_refund` can be called again to re-create
        // the transaction) but mark it executed; it is removed only when the
        // refund is finalized in `verify_refund_finalize`.
        refund_request.executed = true;
        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());
```

**File:** contracts/satoshi-bridge/src/refund.rs (L419-424)
```rust
            !self
                .data()
                .refund_requests
                .contains_key(&utxo_storage_keys[0]),
            "refund request still active"
        );
```

**File:** contracts/satoshi-bridge/src/bitcoin_utils/psbt_wrapper.rs (L127-134)
```rust
    pub fn get_pending_id(&self) -> String {
        self.psbt
            .clone()
            .extract_tx()
            .expect("ERR_EXTRACT_TX: failed to extract transaction from PSBT")
            .compute_txid()
            .to_string()
    }
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L581-589)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn execute_refund(
        &mut self,
        utxo_storage_key: String,
        chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
        self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
    }
```
