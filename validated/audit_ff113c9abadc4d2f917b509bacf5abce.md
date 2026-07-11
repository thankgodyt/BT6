### Title
Silent UTXO Corruption via Oversized `tx_bytes` in `safe_verify_deposit` Permanently Locks Bridge-Controlled BTC — (File: `contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

---

### Summary
In `internal_safe_verify_deposit_entry`, when the submitted `tx_bytes` exceed 10,000 bytes, the code silently replaces the stored transaction bytes with `vec![0u8; 300]` (300 zero bytes) before persisting the UTXO. The deposit proof is verified correctly and nBTC is minted, but the UTXO is permanently stored with invalid bytes, making it unspendable by the bridge for any future withdrawal or UTXO management operation.

---

### Finding Description
At lines 204–209 of `deposit.rs`, `internal_safe_verify_deposit_entry` contains:

```rust
let tx_bytes = if tx_bytes.len() > 10000 {
    env::log_str("tx_bytes length exceeds 10000, truncating to 300 bytes");
    vec![0u8; 300]
} else {
    tx_bytes
};
```

<cite repo="Loderfordw/btc-bridge--018" path="contracts/satoshi-bridge/