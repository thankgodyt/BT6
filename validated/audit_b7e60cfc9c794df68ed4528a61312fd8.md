### Title
UTXO `tx_bytes`/`balance` State Mismatch in Safe Deposit Path Causes Permanent Fund Lock — (File: `contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

---

### Summary

In `internal_safe_verify_deposit_entry`, when the deposit transaction exceeds 10,000 bytes, the UTXO is stored with garbage `tx_bytes` (300 zero bytes) while `balance` is correctly derived from the original transaction. This is a direct analog to the reported vulnerability: two fields that must be consistent are derived from different data sources — `balance` from the real transaction, `tx_bytes` from a zeroed placeholder. When the UTXO is later consumed in the withdrawal PSBT pipeline (which must decode `tx_bytes` to reconstruct the SegWit `witness_utxo`), the garbage bytes cause a decode panic, permanently locking the deposited funds.

---

### Finding Description

In `internal_safe_verify_deposit_entry`, lines 204–215:

```rust
let tx_bytes = if tx_bytes.len() > 10000 {
    env::log_str("tx_bytes length exceeds 10000, truncating to 300 bytes");
    vec![0u8; 300]          // ← garbage: not a valid transaction
} else {
    tx_bytes
};

let utxo = UTXO {
    path,
    tx_bytes,               // ← stored: 300 zero bytes
    vout,
    balance: transaction.output()[vout].value.to_sat(),  // ← correct: from original tx
};
``` [1](#0-0) 

`balance` is computed from the fully-decoded original transaction before the truncation branch. `tx_bytes` is then replaced with `vec![0u8; 300]` — 300 zero bytes that do not represent any valid Bitcoin or Zcash transaction. Both fields are packed into the same `UTXO` struct and persisted together via `safe_mint_callback → internal_set_utxo`. [2](#0-1) 

The non-safe deposit path (`internal_verify_deposit_entry`) stores the full, untruncated `tx_bytes`:

```rust
let utxo = UTXO {
    path,
    tx_bytes,   // full bytes — no truncation
    vout,
    balance: transaction.output()[vout].value.to_sat(),
};
```

<cite repo="Loderfordw/btc-bridge--009" path="contracts/satoshi-bridge/src/bt

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L204-216)
```rust
        let tx_bytes = if tx_bytes.len() > 10000 {
            env::log_str("tx_bytes length exceeds 10000, truncating to 300 bytes");
            vec![0u8; 300]
        } else {
            tx_bytes
        };

        let utxo = UTXO {
            path,
            tx_bytes,
            vout,
            balance: transaction.output()[vout].value.to_sat(),
        };
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L431-438)
```rust
        if is_success {
            Event::UtxoAdded {
                utxo_storage_keys: vec![pending_utxo_info.utxo_storage_key.clone()],
                balances: Some(vec![U128(pending_utxo_info.utxo.balance.into())]),
            }
            .emit();
            self.internal_set_utxo(&pending_utxo_info.utxo_storage_key, pending_utxo_info.utxo);
        } else {
```
