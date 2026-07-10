### Title
Corrupted UTXO `tx_bytes` Storage in `internal_safe_verify_deposit_entry` Permanently Locks Deposited BTC - (File: contracts/satoshi-bridge/src/btc_light_client/deposit.rs)

### Summary
When a Bitcoin transaction exceeding 10,000 bytes is submitted for a safe deposit, the bridge silently replaces the valid `tx_bytes` with 300 zero bytes before storing the UTXO. The deposit is accepted and nBTC is minted, but the stored UTXO contains garbage data. Any subsequent withdrawal attempt that requires decoding those `tx_bytes` to reconstruct the PSBT input will fail, permanently locking the deposited BTC.

### Finding Description
In `internal_safe_verify_deposit_entry`, the transaction is first decoded and fully validated — deposit amount and `script_pubkey` are checked against the derived deposit address. Immediately after that validation, the following block executes:

```rust
// contracts/satoshi-bridge/src/btc_light_client/deposit.rs  lines 204-209
let tx_bytes = if tx_bytes.len() > 10000 {
    env::log_str("tx_bytes length exceeds 10000, truncating to 300 bytes");
    vec![0u8; 300]          // ← replaces with zeros, does NOT truncate
} else {
    tx_bytes
};

let utxo = UTXO {
    path,
    tx_bytes,               // ← stored as 300 zero bytes
    vout,
    balance: transaction.output()[vout].value.to_sat(),
};
```

The comment says "truncating to 300 bytes" but the code produces `vec![0u8; 300]` — 300 zero bytes — not the first 300 bytes of the original transaction. The correctly decoded `transaction` object (used for validation) is discarded; only the zeroed buffer is persisted.

The UTXO's `tx_bytes` field is the sole source of truth for reconstructing the Bitcoin input when building a withdrawal PSBT. The bridge calls `WrappedTransaction::decode(&utxo.tx_bytes, ...)` to obtain the `TxOut` (amount + `script_pubkey`) required for the `witness_utxo` field of the PSBT input. With 300 zero bytes, that decode call panics or returns an error, making every future withdrawal for this UTXO impossible.

The standard deposit path (`internal_verify_deposit_entry`) does not contain this truncation block and is unaffected.

### Impact Explanation
A user whose deposit transaction exceeds 10,000 bytes will:
1. Have their transaction successfully verified by the Light Client.
2. Receive correctly minted nBTC.
3. Find that every subsequent withdrawal attempt panics during PSBT construction because the stored `tx_bytes` are all zeros.
4. Have no on-chain recourse — there is no contract function to update a stored UTXO's `tx_bytes`.

The deposited BTC is permanently locked in the bridge-controlled deposit address. This matches **Critical — Significant loss or permanent locking of user funds**.

### Likelihood Explanation
A Bitcoin transaction exceeds 10,000 bytes when it consolidates roughly 65+ P2WPKH inputs (each ~150 bytes). This is uncommon for a typical single-output deposit but is realistic for users consolidating many dust UTXOs into one deposit. The threshold is also low enough that a moderately active wallet could hit it organically. Because the safe-deposit entry point (`verify_safe_deposit` / `internal_safe_verify_deposit_entry`) is publicly callable by any NEAR account, no privileged access is required to trigger the bug.

### Recommendation
Remove the truncation block entirely. If on-chain storage cost for large transactions is a concern, the correct mitigation is to **reject** the call with a clear error rather than silently corrupt the stored data:

```rust
require!(
    tx_bytes.len() <= MAX_SAFE_DEPOSIT_TX_BYTES,
    "tx_bytes too large for safe deposit"
);
```

This mirrors the existing guard in `request_refund` (`MAX_REQUEST_REFUND_TX_BYTES = 200_000`), which correctly rejects oversized inputs rather than storing garbage.

### Proof of Concept
1. Construct a Bitcoin transaction that consolidates ≥ 67 P2WPKH UTXOs into one output at the bridge deposit address, producing `tx_bytes.len() > 10_000`.
2. Call `verify_safe_deposit` (or the equivalent public entry point) with this transaction, a valid `TxInclusionProof`, and `vout = 0`.
3. The Light Client verifies inclusion; `verify_safe_deposit_callback` fires; nBTC is minted to the recipient.
4. The UTXO is stored with `tx_bytes = vec![0u8; 300]`.
5. Initiate a withdrawal by transferring the nBTC back to the bridge (`ft_transfer_call`). The bridge attempts `WrappedTransaction::decode(&utxo.tx_bytes, &config.chain)` — this panics on the zero buffer.
6. The withdrawal is permanently blocked; the BTC remains locked in the deposit address with no recovery path. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L191-203)
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

```

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

**File:** contracts/satoshi-bridge/src/refund.rs (L26-26)
```rust
pub(crate) const MAX_REQUEST_REFUND_TX_BYTES: usize = 200_000;
```
