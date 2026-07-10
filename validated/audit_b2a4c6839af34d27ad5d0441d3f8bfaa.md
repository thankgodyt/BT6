### Title
Large Deposit Transaction Causes Permanently Stuck UTXO via Silent tx_bytes Zeroing in `internal_safe_verify_deposit_entry` — (File: contracts/satoshi-bridge/src/btc_light_client/deposit.rs)

### Summary

`internal_safe_verify_deposit_entry` silently replaces the raw deposit transaction bytes with 300 zero bytes when the input exceeds 10 000 bytes. The zeroed bytes are stored verbatim in the bridge's UTXO set. Any later attempt to spend that UTXO — during a withdrawal or UTXO-management transaction — will try to deserialize the zeroed bytes as a Bitcoin transaction, which will panic and abort, permanently locking the corresponding BTC inside the bridge address.

### Finding Description

In `contracts/satoshi-bridge/src/btc_light_client/deposit.rs`, `internal_safe_verify_deposit_entry` contains the following block:

```rust
let tx_bytes = if tx_bytes.len() > 10000 {
    env::log_str("tx_bytes length exceeds 10000, truncating to 300 bytes");
    vec![0u8; 300]          // ← replaces with 300 zero bytes, not a truncation
} else {
    tx_bytes
};
``` [1](#0-0) 

The comment says "truncating", but the code discards the original bytes entirely and substitutes `vec![0u8; 300]`. The `UTXO` struct is then constructed with these zeroed bytes:

```rust
let utxo = UTXO {
    path,
    tx_bytes,          // vec![0u8; 300]
    vout,
    balance: transaction.output()[vout].value.to_sat(),
};
``` [2](#0-1) 

`balance` is read from the original (correctly decoded) transaction before the replacement, so the accounting looks correct. However, the stored `tx_bytes` are now invalid. When `safe_mint_callback` succeeds, `internal_set_utxo` adds this corrupted UTXO to the bridge's live UTXO set: [3](#0-2) 

Later, when the bridge selects this UTXO to fund a withdrawal or UTXO-management transaction, it calls `WrappedTransaction::decode(&utxo.tx_bytes, &chain)`. Three hundred zero bytes do not encode a valid Bitcoin transaction; the call will either return an error (triggering `expect("Deserialization tx_bytes failed")`) or decode as a version-0 transaction with zero outputs, causing an out-of-bounds panic when the code accesses `output()[vout]`. Either path aborts the transaction and leaves the UTXO permanently unspendable.

The same code path is reached through the current (non-deprecated) `verify_deposit_v2` whenever `deposit_msg.safe_deposit` is `Some`: [4](#0-3) 

**Attacker-controlled entry path:**
1. Attacker constructs a Bitcoin deposit transaction with many inputs (≥ ~150 P2WPKH inputs ≈ 10 200 bytes) and sends it to a bridge deposit address.
2. The relayer (acting correctly) calls `verify_deposit_v2` with `safe_deposit: Some(...)` and the full raw transaction bytes.
3. The bridge validates the transaction, correctly reads the output value, then replaces `tx_bytes` with `vec![0u8; 300]`.
4. `safe_mint` succeeds; `safe_mint_callback` stores the corrupted UTXO in the live set.
5. The UTXO can never be spent by the bridge.

No privileged access is required beyond the relayer performing its normal duty.

### Impact Explanation

The BTC locked in the deposit UTXO is permanently inaccessible to the bridge's MPC signing pipeline. The bridge has minted the corresponding nBTC (the user received their tokens), but the backing UTXO cannot be included in any future withdrawal PSBT. As the bridge accumulates such stuck UTXOs, its spendable BTC reserve shrinks below the circulating nBTC supply, eventually preventing legitimate withdrawals. Recovery requires a contract upgrade and manual operator intervention. This matches **Medium — stuck bridge state requiring operator intervention**, with a path toward **Critical — permanent locking of protocol funds** if multiple UTXOs are affected.

### Likelihood Explanation

A Bitcoin transaction exceeding 10 000 bytes requires roughly 150+ inputs, which is unusual for a typical deposit but is entirely valid on-chain and can be deliberately constructed by any user who controls many small UTXOs. The relayer has no reason to reject such a transaction; it simply forwards the bytes it observes on-chain. The condition is therefore reachable by any unprivileged user willing to consolidate enough UTXOs into a single deposit transaction.

### Recommendation

Remove the zeroing branch entirely. If oversized transactions must be rejected, do so with an explicit `require!` before any state mutation, rather than silently substituting invalid bytes:

```rust
require!(
    tx_bytes.len() <= MAX_SAFE_DEPOSIT_TX_BYTES,
    "tx_bytes too large for safe deposit"
);
```

If compact storage is the goal, store only the specific output bytes needed for the PSBT `witness_utxo` field (script + value), not a zeroed placeholder.

### Proof of Concept

1. Derive a deposit address via `get_user_deposit_address` with `safe_deposit: Some(SafeDepositMsg { msg: "" })`.
2. Broadcast a Bitcoin transaction with ≥ 150 P2WPKH inputs sending funds to that address (raw tx > 10 000 bytes).
3. Call `verify_deposit_v2` (or `safe_verify_deposit`) with the full `tx_bytes` and `safe_deposit` set.
4. Observe that `safe_mint_callback` succeeds and the UTXO is added to the live set.
5. Attempt any withdrawal that selects this UTXO; observe the contract panic on `WrappedTransaction::decode(&utxo.tx_bytes, ...)` because `tx_bytes` is `[0u8; 300]`. [1](#0-0)

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L204-209)
```rust
        let tx_bytes = if tx_bytes.len() > 10000 {
            env::log_str("tx_bytes length exceeds 10000, truncating to 300 bytes");
            vec![0u8; 300]
        } else {
            tx_bytes
        };
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L211-216)
```rust
        let utxo = UTXO {
            path,
            tx_bytes,
            vout,
            balance: transaction.output()[vout].value.to_sat(),
        };
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L431-437)
```rust
        if is_success {
            Event::UtxoAdded {
                utxo_storage_keys: vec![pending_utxo_info.utxo_storage_key.clone()],
                balances: Some(vec![U128(pending_utxo_info.utxo.balance.into())]),
            }
            .emit();
            self.internal_set_utxo(&pending_utxo_info.utxo_storage_key, pending_utxo_info.utxo);
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L81-91)
```rust
        if deposit_msg.safe_deposit.is_some() {
            self.internal_safe_verify_deposit_entry(
                deposit_msg,
                tx_bytes.0,
                vout,
                proof.tx_block_blockhash,
                proof.tx_index,
                proof.merkle_proof,
                coinbase_proof,
            )
        } else {
```
