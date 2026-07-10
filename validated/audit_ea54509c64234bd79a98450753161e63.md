### Title
Re-execution of `execute_refund` Permanently Blocked by Duplicate `btc_pending_id` — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

The `execute_refund` function is explicitly designed to be re-callable to re-create a refund transaction (e.g., after a consensus branch change). However, `finalize_refund_with_psbt` enforces a strict duplicate-key check on `btc_pending_id` before inserting into `btc_pending_infos`. Because `btc_pending_id` is a deterministic hash of the PSBT signing payloads — which are built entirely from fixed refund-request parameters — the second call always panics with `"pending info already exist"`, permanently blocking refund re-execution and leaving user BTC funds stuck.

---

### Finding Description

**Duplicate check in `finalize_refund_with_psbt`:** [1](#0-0) 

```rust
require!(
    self.data_mut()
        .btc_pending_infos
        .insert(btc_pending_id.clone(), btc_pending_info.into())
        .is_none(),
    "pending info already exist"
);
```

The `btc_pending_id` is derived from `psbt.get_pending_id()`. The underlying ID generator is a pure SHA-256 hash of the PSBT signing payloads with no timestamp or nonce: [2](#0-1) 

```rust
pub fn generate_btc_pending_sign_id(payload_preimages: &[Vec<u8>]) -> String {
    let hash_bytes = env::sha256_array(
        payload_preimages.iter().flatten().copied().collect::<Vec<u8>>(),
    );
    hex::encode(hash_bytes)
}
```

The PSBT is built from the `RefundRequest`'s fixed fields: the same UTXO input (`tx_bytes`, `vout`), the same `refund_amount` (`amount − gas_fee`), and the same `refund_address`. For any given refund request, the PSBT — and therefore `btc_pending_id` — is **identical across every call**.

**Design intent explicitly permits re-execution:** [3](#0-2) 

```rust
// Block only if the UTXO was claimed by a deposit. If it was claimed by
// our own refund (executed == true, which also set verified_deposit_utxo),
// re-running execute_refund is allowed — re-creating the refund tx, e.g.
// after a consensus branch change.
require!(
    !self.data().verified_deposit_utxo.contains(utxo_storage_key)
        || refund_request.executed,
    "UTXO already verified via deposit, cannot refund"
);
```

This guard explicitly passes when `executed == true`, allowing re-entry. But `finalize_refund_with_psbt` never removes the old `btc_pending_info` before attempting to insert the new one with the same key. The insert returns `Some(old_value)`, the `require!` panics, and the re-execution aborts.

**The stuck state cannot be resolved by any public path:**

1. `verify_refund_finalize` requires the refund transaction to be confirmed on-chain — impossible if the tx is unconfirmed (the exact scenario requiring re-execution). [4](#0-3) 

2. `remove_refund_pending_tx_id` requires the refund request to be absent:
   <cite repo="Kohvert/btc-bridge--010" path="contracts/satoshi-bridge/src/refund.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L251-258)
```rust
        // our own refund (executed == true, which also set verified_deposit_utxo),
        // re-running execute_refund is allowed — re-creating the refund tx, e.g.
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

**File:** contracts/satoshi-bridge/src/refund.rs (L462-467)
```rust
    pub fn verify_refund_finalize_callback(&mut self, tx_id: String) -> bool {
        let result_bytes = env::promise_result_checked(0, MAX_BOOL_RESULT)
            .expect("Call verify_transaction_inclusion failed");
        let is_valid = serde_json::from_slice::<bool>(&result_bytes)
            .expect("verify_transaction_inclusion return not bool");
        require!(is_valid, "verify_transaction_inclusion return false");
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
