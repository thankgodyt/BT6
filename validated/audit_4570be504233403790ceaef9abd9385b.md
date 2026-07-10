### Title
`execute_refund` panics on re-execution due to unconditional `BTCPendingInfo` insertion when old entry still exists - (File: `contracts/satoshi-bridge/src/refund.rs`)

### Summary

`execute_refund` is explicitly designed to be callable multiple times to re-create a refund transaction after a consensus branch change. However, `finalize_refund_with_psbt` unconditionally inserts a new `BTCPendingInfo` keyed by a deterministic `btc_pending_id` without first checking whether the old entry from a prior execution still exists. When the old `BTCPendingInfo` is still present (the exact scenario for which re-execution is intended), the second call panics with `"pending info already exist"`, permanently blocking the re-execution path.

### Finding Description

The `RefundRequest.executed` flag and the accompanying comment in `refund.rs` make the re-execution intent explicit:

> "Keep the request (so `execute_refund` can be called again to re-create the transaction) but mark it executed; it is removed only when the refund is finalized in `verify_refund_finalize`." [1](#0-0) 

The guard in `load_refund_request_for_execute` is correctly written to allow re-entry when `executed == true`:

```rust
require!(
    !self.data().verified_deposit_utxo.contains(utxo_storage_key)
        || refund_request.executed,
    "UTXO already verified via deposit, cannot refund"
);
``` [2](#0-1) 

However, `finalize_refund_with_psbt` — called unconditionally on every `execute_refund` invocation — does not check whether a `BTCPendingInfo` with the same `btc_pending_id` already exists before inserting:

```rust
require!(
    self.data_mut()
        .btc_pending_infos
        .insert(btc_pending_id.clone(), btc_pending_info.into())
        .is_none(),
    "pending info already exist"
);
``` [3](#0-2) 

The `btc_pending_id` is derived deterministically from the PSBT content (`psbt.get_pending_id()`). Because the refund PSBT is built from fixed inputs — the same deposit `OutPoint`, the same `deposit_output`, the same `refund_amount` (deposit minus fixed `gas_fee`), and the same `refund_address` — every re-execution of the same refund request produces an identical PSBT and therefore the same `btc_pending_id`. [4](#0-3) 

The old `BTCPendingInfo` is only removed inside `verify_refund_finalize_callback` after the refund transaction is confirmed on-chain: [5](#0-4) 

If the first refund transaction is stuck (the exact scenario motivating re-execution), the old `BTCPendingInfo` remains in `btc_pending_infos`. The second call to `execute_refund` therefore panics at the `require!` above.

The only cleanup path for a stale refund `BTCPendingInfo` is `internal_remove_refund_pending_tx_id`, but it explicitly blocks removal while the refund request is still active:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_keys[0]),
    "refund request still active"
);
``` [6](#0-5) 

Because the refund request is kept alive (with `executed = true`) to enable re-execution, this cleanup path is permanently blocked, creating a deadlock.

### Impact Explanation

**Medium** — Stuck bridge state requiring operator intervention. A user whose refund transaction is stuck (e.g., after a Bitcoin consensus branch change) cannot re-execute the refund. The only operator recovery path is `reject_refund`, which cancels the refund entirely and forces the user to restart the process from scratch, losing the attached storage deposit and the timelock period already served.

### Likelihood Explanation

**Medium** — The re-execution scenario is explicitly documented in the code comments and the `executed` flag was added specifically to support it. Any stuck refund transaction (RBF fee bump failure, chain reorganization, mempool eviction) triggers this path. The entry point (`execute_refund`) is publicly callable by any NEAR account after the timelock. [7](#0-6) 

### Recommendation

In `finalize_refund_with_psbt`, before inserting the new `BTCPendingInfo`, check whether an old entry with the same `btc_pending_id` already exists and remove it (along with its account-level tracking entries) before proceeding:

```rust
// If re-executing an already-executed refund, clean up the stale pending info first.
if self.data().btc_pending_infos.contains_key(&btc_pending_id) {
    let old_info = self.internal_remove_btc_pending_info(&btc_pending_id);
    let account = self.internal_unwrap_mut_account(&old_info.account_id);
    account.btc_pending_sign_ids.remove(&btc_pending_id);
    account.btc_pending_verify_list.remove(&btc_pending_id);
}
```

This mirrors the fix applied in the Caviar report: check the existing state before unconditionally performing the operation.

### Proof of Concept

1. Alice submits a deposit that is never finalized via `verify_deposit`.
2. Alice calls `request_refund` with a valid proof → `RefundRequest` is stored with `executed = false`.
3. After the timelock, anyone calls `execute_refund` → `finalize_refund_with_psbt` succeeds, inserts `BTCPendingInfo` keyed by `btc_pending_id = H`, marks `executed = true`, inserts `utxo_storage_key` into `verified_deposit_utxo`.
4. The refund transaction is stuck on Bitcoin (e.g., due to a chain reorganization — the exact scenario cited in the code comments).
5. Anyone calls `execute_refund` again to re-create the transaction. `load_refund_request_for_execute` passes because `executed == true`. `finalize_refund_with_psbt` is called, builds the identical PSBT, derives the same `btc_pending_id = H`, and hits:
   ```
   require!(...insert(...).is_none(), "pending info already exist")  // PANICS
   ```
6. `remove_refund_pending_tx_id` is called to try to clean up → panics with `"refund request still active"` because the `RefundRequest` is still present.
7. The refund is permanently stuck. The only operator escape is `reject_refund`, which cancels the refund entirely.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L254-258)
```rust
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L336-338)
```rust
        let psbt_hex = psbt.serialize();
        let btc_pending_id = psbt.get_pending_id();

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

**File:** contracts/satoshi-bridge/src/refund.rs (L419-424)
```rust
            !self
                .data()
                .refund_requests
                .contains_key(&utxo_storage_keys[0]),
            "refund request still active"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L487-491)
```rust
        // Clean up: remove pending info
        self.internal_remove_btc_pending_info(&tx_id);
        self.internal_unwrap_mut_account(&account_id)
            .btc_pending_verify_list
            .remove(&tx_id);
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
