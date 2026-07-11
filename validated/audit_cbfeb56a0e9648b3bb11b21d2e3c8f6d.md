### Title
Re-execution of `execute_refund` Always Panics Due to Existing Pending-Sign State - (File: `contracts/satoshi-bridge/src/refund.rs`)

### Summary
`finalize_refund_with_psbt` is explicitly designed to be called multiple times (re-execution of a refund after a consensus branch change), but two hard guards inside it unconditionally panic on any second call, permanently locking the user's refund in an unresolvable stuck state.

### Finding Description
The code in `refund.rs` explicitly documents the re-execution intent:

```rust
// Keep the request (so `execute_refund` can be called again to re-create
// the transaction) but mark it executed; it is removed only when the
// refund is finalized in `verify_refund_finalize`.
refund_request.executed = true;
self.data_mut()
    .refund_requests
    .insert(utxo_storage_key, refund_request.into());
``` [1](#0-0) 

The gate in `load_refund_request_for_execute` also explicitly permits re-entry when `executed == true`:

```rust
require!(
    !self.data().verified_deposit_utxo.contains(utxo_storage_key)
        || refund_request.executed,
    "UTXO already verified via deposit, cannot refund"
);
``` [2](#0-1) 

However, `finalize_refund_with_psbt` — called by every `execute_refund` path — contains two guards that unconditionally panic on a second call:

**Guard 1 — pending-sign capacity check:**

```rust
self.require_pending_sign_capacity(&caller);
``` [3](#0-2) 

`require_pending_sign_capacity` enforces a per-account limit (default: **1**):

```rust
require!(
    self.get_account(account_id)...
        .pending_sign_count()
        < self.get_max_pending_sign_txs(account_id),
    "Too many pending sign transactions"
);
``` [4](#0-3) 

After the first `execute_refund`, the account's `btc_pending_sign_ids` already holds one entry. The second call immediately panics with `"Too many pending sign transactions"`.

**Guard 2 — duplicate pending-info check (applies once the first tx is signed and moves to verify stage):**

```rust
require!(
    self.data_mut()
        .btc_pending_infos
        .insert(btc_pending_id.clone(), btc_pending_info.into())
        .is_none(),
    "pending info already exist"
);
``` [5](#0-4) 

The `btc_pending_id` is derived from the PSBT hash. If the same PSBT is reconstructed (same UTXOs, same refund address, same amounts), the ID is identical and the insert panics. The first pending info is only removed by `verify_refund_finalize_callback`, which requires the refund transaction to confirm on-chain — the exact scenario that necessitates re-execution.

There is no cleanup path available: `internal_remove_refund_pending_tx_id` requires the refund request to be gone (`!refund_requests.contains_key(...)`), but the request is kept alive until finalization. [6](#0-5) 

This is structurally identical to the `safeApprove` class: an operation intended to be repeatable (`execute_refund` re-execution) is blocked by existing non-zero state (the first pending-sign entry), causing every subsequent call to revert.

### Impact Explanation
Once `execute_refund` is called once and the resulting Bitcoin transaction fails to confirm (e.g., due to a chain reorganization or consensus branch change), the refund is permanently stuck:

- The refund request remains in `refund_requests` (kept by design).
- The first `BTCPendingInfo` remains in `btc_pending_infos`.
- The account's `btc_pending_sign_ids` is at capacity.
- Re-execution panics at Guard 1 (or Guard 2 after signing).
- `internal_remove_refund_pending_tx_id` cannot clean up because the refund request is still active.

The user's BTC is locked in the bridge's refund system with no recovery path short of privileged operator intervention (e.g., a DAO-level state migration), which is not provided by any existing API.

This matches: **Low — publicly reachable invariant-violation, stuck-state, or panic-driven fault in production bridge/token paths without direct theft.**

### Likelihood Explanation
Bitcoin chain reorganizations are uncommon but not rare, especially at shallow confirmation depths. Any refund whose first transaction is reorganized out triggers this stuck state. The entry path is fully public: any user who submitted a `request_refund` and whose timelock has elapsed can call `execute_refund`. No privileged role is required to reach the broken code path.

### Recommendation
Before inserting a new `BTCPendingInfo` in `finalize_refund_with_psbt`, check whether a prior refund pending info already exists for this UTXO and remove it (along with its `btc_pending_sign_ids` entry) before proceeding. Specifically:

1. Look up any existing pending info associated with the refund request's UTXO storage key.
2. Remove it from `btc_pending_infos` and from `account.btc_pending_sign_ids` / `btc_pending_verify_list`.
3. Only then insert the new pending info and re-add to `btc_pending_sign_ids`.

This mirrors the fix applied to the original `safeApprove` issue: reset to zero before setting a new non-zero value.

### Proof of Concept

1. User sends BTC to a deposit address and calls `request_refund` with a valid proof. The refund request is stored with `executed: false`.
2. After the timelock elapses, anyone calls `execute_refund`. `finalize_refund_with_psbt` runs:
   - Inserts `btc_pending_id_A` into `btc_pending_infos`. ✓
   - Inserts `btc_pending_id_A` into `account.btc_pending_sign_ids`. ✓
   - Sets `refund_request.executed = true`. ✓
3. The refund Bitcoin transaction is broadcast but is reorganized out of the chain before confirming.
4. Anyone calls `execute_refund` again (explicitly permitted by `executed == true` check and the code comment).
5. `finalize_refund_with_psbt` runs again:
   - `require_pending_sign_capacity` → `pending_sign_count() == 1 >= limit(1)` → **PANIC: "Too many pending sign transactions"**.
6. The refund request cannot be finalized, rejected (operator reject removes the request but leaves the stale pending info), or re-executed. The user's BTC value is permanently locked in the bridge's refund accounting.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L254-258)
```rust
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L342-342)
```rust
        self.require_pending_sign_capacity(&caller);
```

**File:** contracts/satoshi-bridge/src/refund.rs (L366-372)
```rust
        require!(
            self.data_mut()
                .btc_pending_infos
                .insert(btc_pending_id.clone(), btc_pending_info.into())
                .is_none(),
            "pending info already exist"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L395-401)
```rust
        // Keep the request (so `execute_refund` can be called again to re-create
        // the transaction) but mark it executed; it is removed only when the
        // refund is finalized in `verify_refund_finalize`.
        refund_request.executed = true;
        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());
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

**File:** contracts/satoshi-bridge/src/account.rs (L113-123)
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
    }
```
