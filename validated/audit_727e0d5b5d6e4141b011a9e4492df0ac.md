### Title
Silent Replacement of Large `tx_bytes` with Zeroed Buffer Permanently Locks Bridge UTXOs - (File: `contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

---

### Summary

In `internal_safe_verify_deposit_entry`, when the caller-supplied `tx_bytes` exceeds 10,000 bytes, the code silently replaces the real transaction bytes with a 300-byte zero buffer before storing the UTXO. Deposit validity (amount, script_pubkey) is checked against the **real** bytes, but the **zeroed** bytes are persisted. Any subsequent attempt by the bridge to spend that UTXO will fail to deserialize the stored bytes, permanently locking the corresponding BTC inside the bridge.

---

### Finding Description

`internal_safe_verify_deposit_entry` performs all correctness checks against the original `tx_bytes`, then overwrites them:

```rust
// lines 191-202: validation uses the REAL tx_bytes
let transaction = WrappedTransaction::decode(&tx_bytes, &self.internal_config().chain)
    .expect("Deserialization tx_bytes failed");
let deposit_amount = transaction.output()[vout].value.to_sat().into();
require!(deposit_amount > 0, "Invalid deposit_amount");
...
require!(
    deposit_address_script_pubkey == transaction.output()[vout].script_pubkey,
    "Invalid deposit tx_bytes"
);

// lines 204-209: UTXO is stored with ZEROED tx_bytes
let tx_bytes = if tx_bytes.len() > 10000 {
    env::log_str("tx_bytes length exceeds 10000, truncating to 300 bytes");
    vec![0u8; 300]          // ← real bytes discarded, zeros stored
} else {
    tx_bytes
};

let utxo = UTXO {
    path,
    tx_bytes,               // ← zeroed buffer
    vout,
    balance: transaction.output()[vout].value.to_sat(),
};
``` [1](#0-0) 

Every downstream path that needs to spend this UTXO calls `WrappedTransaction::decode(&utxo.tx_bytes, ...)`, which will panic on 300 zero bytes:

```rust
let transaction = WrappedTransaction::decode(&tx_bytes, &self.internal_config().chain)
    .expect("Deserialization tx_bytes failed");
``` [2](#0-1) 

The same decode call appears in the withdrawal burn callback and refund execution paths, meaning the UTXO can never be consumed. [3](#0-2) [4](#0-3) 

---

### Impact Explanation

Once a UTXO is stored with zeroed `tx_bytes`, the bridge has no mechanism to update or replace it. Every attempt to use it as a PSBT input panics. The BTC value locked in that UTXO is permanently irrecoverable by the bridge, reducing the pool of spendable UTXOs and eventually making the bridge unable to fulfill withdrawals. This matches **Critical — significant permanent locking of protocol funds**.

---

### Likelihood Explanation

A Bitcoin transaction exceeds 10,000 bytes when it consolidates roughly 140+ P2WPKH inputs (each ~68 bytes). An attacker can deliberately accumulate many dust UTXOs at their deposit address and then sweep them in a single large transaction. The `safe_verify_deposit` entry point is public and payable; any NEAR account that attaches the required storage deposit can submit the proof. No privileged role is required. [5](#0-4) 

---

### Recommendation

Remove the silent truncation entirely. If oversized transactions must be rejected, do so with an explicit `require!` before any state is written:

```rust
require!(
    tx_bytes.len() <= 10_000,
    "tx_bytes exceeds maximum allowed size"
);
```

This ensures the function either stores valid, decodable bytes or reverts cleanly, with no silent data corruption.

---

### Proof of Concept

1. Attacker accumulates 150+ small UTXOs at their bridge deposit address (derived from their NEAR account via `get_deposit_path`).
2. Attacker broadcasts a single Bitcoin consolidation transaction spending all 150 inputs into the deposit address output. The raw transaction is ~10,200 bytes.
3. Attacker (or any relayer) calls `safe_verify_deposit` on NEAR with the large `tx_bytes`, valid `vout`, Merkle proof, and the required storage deposit.
4. `internal_safe_verify_deposit_entry` validates the deposit amount and script_pubkey against the real bytes (passes), then replaces `tx_bytes` with `vec![0u8; 300]`.
5. The UTXO is stored with zeroed bytes; nBTC is minted to the recipient.
6. Any future withdrawal or refund that selects this UTXO calls `WrappedTransaction::decode(&[0u8; 300], ...)`, which panics with "Deserialization tx_bytes failed".
7. The BTC value of that UTXO is permanently locked; the bridge's spendable UTXO pool is permanently reduced.

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L181-184)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_safe_deposit(),
            "Insufficient deposit for storage"
        );
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L191-216)
```rust
        let transaction = WrappedTransaction::decode(&tx_bytes, &self.internal_config().chain)
            .expect("Deserialization tx_bytes failed");
        let deposit_amount = transaction.output()[vout].value.to_sat().into();
        require!(deposit_amount > 0, "Invalid deposit_amount");
        let deposit_address = self.generate_utxo_chain_address(&path);
        let deposit_address_script_pubkey = deposit_address
            .script_pubkey()
            .expect("Invalid deposit address");
        require!(
            deposit_address_script_pubkey == transaction.output()[vout].script_pubkey,
            "Invalid deposit tx_bytes"
        );

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

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L249-251)
```rust
        let transaction = WrappedTransaction::decode(&tx_bytes, &config.chain)
            .expect("Deserialization tx_bytes failed");
        let deposit_amount = u128::from(transaction.output()[vout].value.to_sat());
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L79-81)
```rust
            let tx_bytes = btc_pending_info.tx_bytes_with_sign.as_ref().unwrap();
            let transaction = WrappedTransaction::decode(tx_bytes, &self.internal_config().chain)
                .expect("Deserialization tx_bytes failed");
```

**File:** contracts/satoshi-bridge/src/refund.rs (L269-271)
```rust
        let transaction =
            crate::WrappedTransaction::decode(&refund_request.tx_bytes.0, &config.chain)
                .expect("Deserialization tx_bytes failed");
```
