### Title
Refund `BTCPendingInfo` in `PendingSign` State Has No Expiry and Cannot Be User-Cancelled — (`contracts/satoshi-bridge/src/btc_pending_info.rs`, `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

Once `execute_refund` builds a refund PSBT and stores a `BTCPendingInfo` in `PendingInfoState::Refund(PendingSign)`, that pending entry persists indefinitely with no expiry and no user-accessible cancellation path. The `do_cancel` function explicitly panics for the `Refund` variant. If MPC signing stalls or fails permanently, the deposit UTXO is simultaneously blocked from being claimed as a deposit (it is inserted into `verified_deposit_utxo`) and the refund pending info cannot be cleared by the user, leaving the bridge in a stuck state that requires operator intervention.

---

### Finding Description

**Root cause — `do_cancel` rejects `Refund` state:** [1](#0-0) 

```rust
pub fn do_cancel(&mut self, gas_fee: u128, cancel_rbf_reserved: u128) {
    match self.state.borrow_mut() {
        PendingInfoState::WithdrawOriginal(state) => { ... }
        PendingInfoState::ActiveUtxoManagementOriginal(state) => { ... }
        _ => env::panic_str("Not original tx"),   // ← Refund hits this branch
    }
}
```

Withdrawal-type pending infos have an RBF-cancel escape hatch; refund-type pending infos have none.

**Root cause — `finalize_refund_with_psbt` marks the UTXO verified and keeps the request:** [2](#0-1) 

After `execute_refund` succeeds:
1. The deposit UTXO key is inserted into `verified_deposit_utxo` — blocking any future `verify_deposit` call for that UTXO.
2. The `RefundRequest` is kept with `executed = true` — it is never removed until `verify_refund_finalize_callback` succeeds.
3. A `BTCPendingInfo` in `Refund(PendingSign)` is stored — it has no `expires_at` field and no user-callable removal path.

**Root cause — `load_refund_request_for_execute` has no upper-bound expiry:** [3](#0-2) 

The only time check is a *lower* bound (`now >= created_at + timelock`). There is no upper bound. The request and its associated pending info remain valid indefinitely.

**Root cause — `BTCPendingInfo` struct carries no expiry field:** [4](#0-3) 

`create_time_sec` and `last_sign_time_sec` are recorded for observability only; no code path enforces a deadline on the `PendingSign` stage.

**The only cleanup path for a stuck refund pending info is `internal_remove_refund_pending_tx_id`:** [5](#0-4) 

This function requires the `RefundRequest` to already be gone (`!refund_requests.contains_key(...)`). But the `RefundRequest` is only removed by `verify_refund_finalize_callback` (on-chain confirmation) or `internal_reject_refund` (operator action). Neither is user-callable in the stuck scenario.

---

### Impact Explanation

If MPC signing stalls or permanently fails after `execute_refund`:

- The deposit UTXO is in `verified_deposit_utxo` → `verify_deposit` is blocked for that UTXO.
- The `BTCPendingInfo` is in `Refund(PendingSign)` → user cannot cancel it.
- The `RefundRequest` remains with `executed = true` → `execute_refund` can be re-called, but only creates a new pending info with the same deterministic PSBT ID, which fails with "pending info already exist" while the old one is still present.
- The user's deposited BTC is effectively frozen: it cannot be minted as nBTC (UTXO is verified) and the refund cannot complete without operator intervention.

This matches the allowed Medium impact: **stuck bridge state requiring operator intervention**.

---

### Likelihood Explanation

MPC signing failures are a realistic operational scenario (network partitions, key rotation, MPC node downtime). Any user who calls `execute_refund` on a UTXO during such a window will have their funds frozen with no self-service recovery. The entry path is fully public and unprivileged — any bridge user who submitted a refund request can trigger this state.

---

### Recommendation

1. **Add an expiry to `BTCPendingInfo` in `Refund` state.** After a configurable deadline (e.g., `refund_pending_sign_timeout_sec`), allow the user or a relayer to call a `cancel_refund_pending_sign` function that removes the pending info and resets `refund_request.executed = false`, re-enabling a fresh `execute_refund` call.

2. **Extend `do_cancel` to handle `PendingInfoState::Refund`.** The cancel path should clear the pending info and reset the `executed` flag on the associated `RefundRequest` so the refund can be retried.

3. **Remove the UTXO from `verified_deposit_utxo` on cancellation.** If the refund pending info is cancelled before the refund tx is confirmed, the UTXO should be unblocked so `verify_deposit` remains possible as a fallback.

---

### Proof of Concept

1. User sends BTC to a deposit address but the deposit is not claimed (e.g., wrong `deposit_msg`). User calls `request_refund(...)` — `RefundRequest` is stored.
2. Timelock elapses. User (or anyone) calls `execute_refund(...)`. `finalize_refund_with_psbt` runs:
   - UTXO inserted into `verified_deposit_utxo`.
   - `BTCPendingInfo` created in `Refund(PendingSign)`.
   - `refund_request.executed = true`.
3. MPC network is unavailable. `sign_btc_transaction` is called but the callback returns failure. `BTCPendingInfo` remains in `PendingSign` with no signature.
4. User attempts to cancel: `do_cancel` panics — "Not original tx".
5. User attempts to call `execute_refund` again: `finalize_refund_with_psbt` hits `require!(...insert(...).is_none(), "pending info already exist")` — reverts.
6. User's BTC is frozen: `verify_deposit` is blocked by `verified_deposit_utxo`; refund cannot complete; no user-callable exit exists. Operator must call `internal_reject_refund` then `internal_remove_refund_pending_tx_id` to unblock.

### Citations

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L107-127)
```rust
pub struct BTCPendingInfo {
    pub account_id: AccountId,
    pub btc_pending_id: String,
    #[serde(with = "u128_dec_format")]
    pub transfer_amount: u128,
    #[serde(with = "u128_dec_format")]
    pub actual_received_amount: u128,
    #[serde(with = "u128_dec_format")]
    pub withdraw_fee: u128,
    #[serde(with = "u128_dec_format")]
    pub gas_fee: u128,
    #[serde(with = "u128_dec_format")]
    pub burn_amount: u128,
    pub psbt_hex: String,
    pub vutxos: Vec<VUTXO>,
    pub signatures: Vec<Option<SignatureResponse>>,
    pub tx_bytes_with_sign: Option<Vec<u8>>,
    pub create_time_sec: u32,
    pub last_sign_time_sec: u32,
    pub state: PendingInfoState,
}
```

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L271-285)
```rust
    pub fn do_cancel(&mut self, gas_fee: u128, cancel_rbf_reserved: u128) {
        match self.state.borrow_mut() {
            PendingInfoState::WithdrawOriginal(state) => {
                state.max_gas_fee = gas_fee;
                state.last_rbf_time_sec = Some(nano_to_sec(env::block_timestamp()));
                state.cancel_rbf_reserved = Some(cancel_rbf_reserved.into());
            }
            PendingInfoState::ActiveUtxoManagementOriginal(state) => {
                state.max_gas_fee = gas_fee;
                state.last_rbf_time_sec = Some(nano_to_sec(env::block_timestamp()));
                state.cancel_rbf_reserved = Some(cancel_rbf_reserved.into());
            }
            _ => env::panic_str("Not original tx"),
        }
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L244-261)
```rust
        let now = nano_to_sec(env::block_timestamp());
        require!(
            u64::from(now) >= u64::from(refund_request.created_at_sec) + timelock_sec,
            "Refund timelock has not passed yet"
        );

        // Block only if the UTXO was claimed by a deposit. If it was claimed by
        // our own refund (executed == true, which also set verified_deposit_utxo),
        // re-running execute_refund is allowed — re-creating the refund tx, e.g.
        // after a consensus branch change.
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );

        refund_request
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L377-401)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L408-431)
```rust
    pub(crate) fn internal_remove_refund_pending_tx_id(&mut self, tx_id: String) {
        let btc_pending_info = self.internal_unwrap_btc_pending_info(&tx_id).clone();
        btc_pending_info.assert_refund_related();

        // A refund spends exactly one deposit UTXO, whose key is the refund request key.
        let utxo_storage_keys = btc_pending_info.get_psbt().get_utxo_storage_keys();
        require!(
            utxo_storage_keys.len() == 1,
            "refund transaction must spend exactly one input"
        );
        require!(
            !self
                .data()
                .refund_requests
                .contains_key(&utxo_storage_keys[0]),
            "refund request still active"
        );

        let account_id = btc_pending_info.account_id.clone();
        self.internal_remove_btc_pending_info(&tx_id);
        let account = self.internal_unwrap_mut_account(&account_id);
        account.btc_pending_sign_ids.remove(&tx_id);
        account.btc_pending_verify_list.remove(&tx_id);
    }
```
