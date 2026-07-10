### Title
Silent Replacement of Deposit `tx_bytes` with Zero-Filled Buffer Causes Permanently Stuck UTXOs — (File: `contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

---

### Summary

In `internal_safe_verify_deposit_entry`, when the caller-supplied `tx_bytes` exceed 10,000 bytes, the function silently discards the real transaction bytes and stores a 300-byte all-zero buffer in their place. The UTXO is then added to the bridge's live UTXO pool with this corrupted `tx_bytes` field. For Zcash deposits that include an Orchard bundle — which routinely exceed 10,000 bytes — this produces a UTXO whose stored bytes cannot be decoded as a valid transaction, permanently blocking any future spend of that UTXO and locking the deposited funds.

---

### Finding Description

`internal_safe_verify_deposit_entry` contains the following branch:

```rust
// contracts/satoshi-bridge/src/btc_light_client/deposit.rs  lines 204-209
let tx_bytes = if tx_bytes.len() > 10000 {
    env::log_str("tx_bytes length exceeds 10000, truncating to 300 bytes");
    vec![0u8; 300]          // ← NOT a truncation; replaces with 300 zero bytes
} else {
    tx_bytes
};
```

The comment says "truncating to 300 bytes", but the code does not keep the first 300 bytes of the real transaction — it produces a fresh 300-byte zero-filled `Vec`. The real transaction bytes are thrown away entirely. [1](#0-0) 

Immediately after, the zeroed buffer is embedded in the `UTXO` struct and forwarded through the callback chain:

```rust
let utxo = UTXO {
    path,
    tx_bytes,          // ← 300 zero bytes
    vout,
    balance: transaction.output()[vout].value.to_sat(),
};
``` [2](#0-1) 

`safe_mint_callback` then persists this UTXO into the bridge's live pool via `internal_set_utxo`:

```rust
self.internal_set_utxo(&pending_utxo_info.utxo_storage_key, pending_utxo_info.utxo);
``` [3](#0-2) 

The `balance` and `path` fields are computed correctly from the real transaction before the replacement, so the bridge's accounting is correct — but the `tx_bytes` field, which is required to reconstruct the spending input for the Zcash PSBT signer, is permanently invalid.

The Zcash signing path explicitly acknowledges that Zcash transactions with Orchard bundles are large:

```rust
// For ZCash chains, use base64 encoding to save space (1.33x vs 2x overhead for hex)
// ZCash transactions with Orchard bundles are larger and benefit from compact encoding
``` [4](#0-3) 

A Zcash transaction carrying an Orchard bundle easily exceeds 10,000 bytes, making this branch reachable in normal Zcash deposit usage.

---

### Impact Explanation

Once a UTXO with zeroed `tx_bytes` is in the pool, any attempt to spend it via the Zcash PSBT path will fail: the PSBT wrapper must decode the stored `tx_bytes` to reconstruct the input's previous-output data for signing. Decoding 300 zero bytes as a Zcash transaction will panic or return an error, leaving the UTXO permanently unspendable. The deposited ZEC is locked inside the bridge with no recovery path short of a contract upgrade and manual state surgery by the operator.

This matches the **Medium** impact class: *broken callback / stuck bridge state requiring operator intervention*, and *attacker-triggered (or user-triggered) temporary/permanent locking of bridged funds*.

---

### Likelihood Explanation

Any Zcash deposit transaction that includes an Orchard shielded bundle will exceed 10,000 bytes. This is a normal, expected transaction type for the Zcash bridge path (the codebase explicitly handles Orchard bundles throughout `zcash_utils/`). No special attacker capability is required — an ordinary user depositing ZEC via a shielded Unified Address triggers the branch automatically. Likelihood is **Medium-High** for the Zcash path.

---

### Recommendation

Remove the silent replacement entirely. If oversized `tx_bytes` must be rejected, do so explicitly with a `require!` / `panic_str` before any state is written, so the transaction is cleanly rejected rather than silently corrupted:

```rust
require!(
    tx_bytes.len() <= MAX_SAFE_DEPOSIT_TX_BYTES,
    "tx_bytes too large for safe deposit"
);
```

Do not store a zero-filled buffer as a substitute for real transaction data.

---

### Proof of Concept

1. A user constructs a Zcash withdrawal-to-bridge transaction that includes an Orchard bundle (routine for shielded ZEC). The serialized transaction exceeds 10,000 bytes.
2. The user calls `safe_verify_deposit` (the public entry point for `internal_safe_verify_deposit_entry`) with the real `tx_bytes`.
3. The branch at line 205 fires; `tx_bytes` is replaced with `vec![0u8; 300]`.
4. After light-client verification succeeds, `safe_mint_callback` stores the UTXO with zeroed `tx_bytes` in the bridge's UTXO pool and mints nZEC to the user.
5. Later, when the bridge attempts to spend this UTXO (withdrawal or active UTXO management), `generate_vutxos` retrieves the UTXO; the Zcash PSBT wrapper attempts to decode the stored `tx_bytes` to build the signing input and fails.
6. The UTXO is permanently unspendable; the deposited ZEC is locked in the bridge. [5](#0-4)

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

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L437-437)
```rust
            self.internal_set_utxo(&pending_utxo_info.utxo_storage_key, pending_utxo_info.utxo);
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L175-177)
```rust
                // ZCash transactions with Orchard bundles are larger and benefit from compact encoding
                // For Bitcoin chains, keep hex encoding for backward compatibility

```
