### Title
Re-Enterable `execute_refund` Creates Unbounded Stale `BTCPendingInfo` Entries — Missing "Awaiting Confirmation" Guard - (File: `contracts/satoshi-bridge/src/refund.rs`)

### Summary
The refund state machine in `refund.rs` intentionally allows `execute_refund` to be called repeatedly on an already-executed refund request (when `executed == true`). Each call unconditionally creates a new `BTCPendingInfo` entry in `PendingSign` state, consuming pending-sign capacity and accumulating stale entries that can never be finalized. There is no "awaiting confirmation" state to block re-entry once the refund transaction has already been built and submitted — a direct analog to the Arbitrum edge-tracker loop described in the external report.

---

### Finding Description

`load_refund_request_for_execute` contains an explicit bypass that permits re-execution when the refund has already been executed: [1](#0-0) 

```rust
require!(
    !self.data().verified_deposit_utxo.contains(utxo_storage_key)
        || refund_request.executed,   // ← bypass: re-execution allowed when executed == true
    "UTXO already verified via deposit, cannot refund"
);
```

The design intent (stated in the comment at line 395–397) is to allow re-creating the refund transaction after a consensus branch change. However, `finalize_refund_with_psbt` — called unconditionally on every successful `execute_refund` — creates a **brand-new** `BTCPendingInfo` each time: [2](#0-1) 

Specifically:
1. `require_pending_sign_capacity(&caller)` is checked (line 342) — it does not account for already-existing pending infos for the same UTXO.
2. A new `btc_pending_id` is derived from the new PSBT hash (line 337).
3. The new `BTCPendingInfo` is inserted into `btc_pending_infos` (line 366–372) and into `account.btc_pending_sign_ids` (line 373–375).
4. `verified_deposit_utxo.insert` is called again (line 378–380) — a no-op since the key is already present.
5. The refund request is re-saved with `executed: true` (line 398–401) — also a no-op.

The net result: every call to `execute_refund` after the first produces a new `BTCPendingInfo` in `PendingSign` state for the same underlying UTXO. Only one refund transaction can ever confirm on-chain (they all spend the same UTXO), so all but one become permanently stale. [3](#0-2) 

The cleanup path (`internal_remove_refund_pending_tx_id`) requires the refund request to already be gone: [4](#0-3) 

This means stale entries cannot be cleaned up until after `verify_refund_finalize_callback` removes the request — which itself requires one of the competing transactions to confirm on-chain first.

---

### Impact Explanation

**Medium — Stuck bridge state requiring operator intervention.**

- Multiple `BTCPendingInfo` entries accumulate for the same UTXO, each in `PendingSign` state.
- Each entry occupies a slot in `btc_pending_sign_ids`, consuming the account's pending-sign capacity.
- Stale entries cannot be cleaned up via `internal_remove_refund_pending_tx_id` until the refund request is removed (which requires on-chain confirmation of one competing tx).
- If pending-sign capacity is exhausted across multiple accounts (via multiple callers), the bridge's refund signing pipeline stalls, requiring operator intervention to manually clean up stale entries.
- No direct theft of funds occurs, but the refund UTXO is locked in a contested pending state with multiple competing unsigned transactions, and the bridge cannot self-recover without operator action.

---

### Likelihood Explanation

**Medium.**

- `execute_refund` is a public, permissionless function callable by any NEAR account after the timelock elapses.
- The timelock (`refund_timelock_sec` or `unsafe_refund_timelock_sec`) is a fixed delay, not a one-time gate — once elapsed, the function can be called indefinitely.
- Each call requires an attached deposit (`required_balance_for_execute_refund`), which limits free spam but does not prevent a motivated attacker from making several calls.
- The attacker only needs one valid, already-executed refund request (`executed == true`) to trigger the issue.

---

### Recommendation

Add a guard in `load_refund_request_for_execute` (or at the top of `finalize_refund_with_psbt`) that checks whether a `BTCPendingInfo` already exists for the UTXO's storage key before creating a new one. If one exists and is still in `PendingSign` or `PendingVerify` state, reject the re-execution with a clear error. Alternatively, introduce an explicit `AwaitingConfirmation` stage in `PendingInfoStage` that is set after the first successful `execute_refund`, and only allow re-execution if the previous pending info has been cleaned up or confirmed. [5](#0-4) 

---

### Proof of Concept

1. Alice submits a deposit to the bridge UTXO address.
2. Alice (or anyone) calls `request_refund` with a valid inclusion proof. The refund request is stored with `executed: false`.
3. After the timelock elapses, Alice calls `execute_refund`. `finalize_refund_with_psbt` runs: a `BTCPendingInfo` (`id_1`) is created, `executed` is set to `true`, and the UTXO is added to `verified_deposit_utxo`.
4. An attacker (or Alice herself) calls `execute_refund` again. `load_refund_request_for_execute` passes because `executed == true` satisfies the bypass condition. `finalize_refund_with_psbt` runs again: a second `BTCPendingInfo` (`id_2`) is created under the attacker's account.
5. Steps 4 can be repeated (with different caller accounts to bypass per-account capacity limits), creating `id_3`, `id_4`, … each consuming pending-sign capacity.
6. Each `BTCPendingInfo` can be independently submitted to `sign_btc_transaction`, triggering MPC signing for competing transactions that all spend the same UTXO.
7. Only one transaction can confirm on-chain. `verify_refund_finalize_callback` removes the refund request. All other `BTCPendingInfo` entries (`id_2`, `id_3`, …) are now permanently stale — `internal_remove_refund_pending_tx_id` can clean them up, but only after the refund request is gone, requiring operator awareness and manual intervention.

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

**File:** contracts/satoshi-bridge/src/refund.rs (L339-375)
```rust
        if !self.check_account_exists(&caller) {
            self.internal_set_account(&caller, crate::Account::new(&caller));
        }
        self.require_pending_sign_capacity(&caller);

        let btc_pending_info = BTCPendingInfo {
            account_id: caller.clone(),
            btc_pending_id: btc_pending_id.clone(),
            transfer_amount: 0,
            actual_received_amount: refund_amount,
            withdraw_fee: 0,
            gas_fee,
            burn_amount: 0,
            psbt_hex,
            vutxos: vec![vutxo],
            signatures: vec![None; 1],
            tx_bytes_with_sign: None,
            create_time_sec: nano_to_sec(env::block_timestamp()),
            last_sign_time_sec: 0,
            state: PendingInfoState::Refund(OriginalState {
                stage: PendingInfoStage::PendingSign,
                max_gas_fee: gas_fee,
                last_rbf_time_sec: None,
                cancel_rbf_reserved: None,
            }),
        };

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

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L60-64)
```rust
pub enum PendingInfoStage {
    PendingSign,
    PendingVerify,
    PendingBurn,
}
```
