### Title
Re-execution of `execute_refund` Permanently Blocked by Conflicting State Assumption in `finalize_refund_with_psbt` — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`finalize_refund_with_psbt` unconditionally asserts that the derived `btc_pending_id` does not already exist in `btc_pending_infos`. However, the contract explicitly permits re-execution of `execute_refund` when `refund_request.executed == true`. Because a refund PSBT is fully deterministic (fixed UTXO input, fixed `refund_address`, fixed `gas_fee`), the `btc_pending_id` is identical on every re-execution attempt. The `require!` therefore always panics on the second call, permanently blocking re-execution and leaving the refund stuck. Any unprivileged caller can exploit this by frontrunning a victim's `execute_refund` call, seizing ownership of the `BTCPendingInfo`, and then refusing to sign — locking the victim's BTC until a DAO/Operator intervenes.

---

### Finding Description

`load_refund_request_for_execute` explicitly allows re-execution when the request is already marked `executed`: [1](#0-0) 

The comment reads: *"re-running execute_refund is allowed — re-creating the refund tx, e.g. after a consensus branch change."*

However, `finalize_refund_with_psbt` — called unconditionally by every execution path — contains: [2](#0-1) 

The `btc_pending_id` is a SHA-256 hash of the PSBT signing payloads (`generate_btc_pending_sign_id`): [3](#0-2) 

A refund PSBT is fully determined by the stored `RefundRequest` fields — the deposit UTXO (`tx_bytes` + `vout`), the `refund_address`, and the `gas_fee` — all of which are immutable after `request_refund_callback` stores them: [4](#0-3) 

Because none of these fields can change between calls, the PSBT is byte-for-byte identical on every re-execution, producing the same `btc_pending_id`. The first execution inserts the entry; the second execution hits `is_none()` == `false` and panics with *"pending info already exist"*.

The first execution also inserts the UTXO into `verified_deposit_utxo` and keeps the `RefundRequest` with `executed = true`: [5](#0-4) 

After the first execution the victim cannot:
- Re-execute (same `btc_pending_id` → panic).
- Remove the stale pending info via `remove_refund_pending_tx_id` — that function requires the refund request to be absent, but it is still present with `executed = true`: [6](#0-5) 

- Permissionlessly reject the request — `reject_refund` sets `is_already_deposited = !executed && verified_deposit_utxo.contains(...)`, which is `false` when `executed == true`, so only DAO/Operator can reject: [7](#0-6) 

The only escape is DAO/Operator intervention.

---

### Impact Explanation

An attacker who frontrunning calls `execute_refund` for a victim's request becomes the `account_id` of the resulting `BTCPendingInfo`. The victim's BTC is locked in the bridge: the victim cannot re-execute, cannot remove the stale pending entry, and cannot permissionlessly reject the request. The refund remains stuck until a privileged operator manually rejects the request and cleans up the stale pending info. This matches the allowed impact: **attacker-triggered temporary locking of bridged funds requiring operator intervention**.

---

### Likelihood Explanation

`execute_refund` is a public, payable function with no access-control restriction beyond the timelock and a small NEAR storage deposit. Any NEAR account can call it for any pending refund request after the timelock expires. The attacker cost is only the NEAR storage deposit (`required_balance_for_execute_refund()`). The victim has no on-chain defense once the attacker's call lands first.

---

### Recommendation

Before inserting a new `BTCPendingInfo` in `finalize_refund_with_psbt`, check whether an entry for the same `btc_pending_id` already exists and, if so, remove the stale entry (or skip insertion and reuse it). Alternatively, remove the old `BTCPendingInfo` and its associated `btc_pending_sign_ids` entry at the start of re-execution before building the new PSBT. This mirrors the mitigation suggested in the reference report: update the tracked state before the operation that assumes uniqueness.

---

### Proof of Concept

1. Alice submits `request_refund` for a deposit UTXO; the timelock elapses.
2. Attacker (Bob) calls `execute_refund(alice_utxo_key)` with the required NEAR deposit.
   - `finalize_refund_with_psbt` inserts `BTCPendingInfo{account_id: Bob, btc_pending_id: H1}`.
   - `verified_deposit_utxo` now contains `alice_utxo_key`.
   - `RefundRequest.executed` is set to `true`.
3. Bob does not call `sign_btc_transaction`; the refund transaction is never broadcast.
4. Alice calls `execute_refund(alice_utxo_key)` to retry.
   - `load_refund_request_for_execute` passes (executed == true bypasses the UTXO check).
   - `finalize_refund_with_psbt` builds the identical PSBT → same `btc_pending_id = H1`.
   - `btc_pending_infos.insert(H1, ...)` returns `Some(...)` (already present).
   - `require!` panics: **"pending info already exist"**.
5. Alice cannot call `remove_refund_pending_tx_id(H1)` — the refund request is still active.
6. Alice cannot permissionlessly call `reject_refund` — `executed == true` disables the public path.
7. Alice's BTC is locked until DAO/Operator rejects the request and removes the stale pending info.

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

**File:** contracts/satoshi-bridge/src/refund.rs (L564-578)
```rust
        let refund_request = RefundRequest {
            deposit_msg_json: serde_json::to_string(&deposit_msg).unwrap(),
            utxo_storage_key: utxo_storage_key.clone(),
            tx_bytes,
            vout,
            amount,
            refund_address,
            gas_fee: resolved_gas_fee,
            created_at_sec: nano_to_sec(env::block_timestamp()),
            executed: false,
        };

        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());
```

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L416-425)
```rust
pub fn generate_btc_pending_sign_id(payload_preimages: &[Vec<u8>]) -> String {
    let hash_bytes = env::sha256_array(
        payload_preimages
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<u8>>(),
    );
    hex::encode(hash_bytes)
}
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L553-568)
```rust
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
```
