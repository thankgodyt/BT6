### Title
Bitcoin Transaction-Malleability Reorg Enables Double-Mint of nBTC — (File: `contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

### Summary

The bridge deduplicates deposits using a `verified_deposit_utxo` set keyed by `{tx_id}@{vout}`. The `tx_id` is computed directly from the raw transaction bytes supplied by the relayer. For legacy (non-SegWit) Bitcoin transactions, the transaction ID is derived from data that includes the scriptSig/signature, which is malleable. If a Bitcoin reorg occurs and a malleated variant of the same economic deposit is confirmed in the reorganised chain, the deduplication key changes, and the bridge will mint nBTC a second time for the same underlying BTC.

### Finding Description

In `internal_verify_deposit_entry`, the bridge computes the UTXO storage key entirely from the decoded transaction bytes:

```rust
let tx_id = transaction.compute_txid().to_string();
let utxo_storage_key = generate_utxo_storage_key(
    tx_id.clone(),
    u32::try_from(vout)...,
);
``` [1](#0-0) 

`generate_utxo_storage_key` simply concatenates `tx_id` and `vout` with `@`: [2](#0-1) 

In `verify_deposit_callback`, the only deduplication guard is:

```rust
require!(
    self.data_mut()
        .verified_deposit_utxo
        .insert(pending_utxo_info.utxo_storage_key.clone()),
    "Already deposit utxo"
);
``` [3](#0-2) 

The same pattern appears in `verify_safe_deposit_callback` and `unavailable_utxo_callback`. [4](#0-3) 

For legacy (non-SegWit) Bitcoin transactions, the `txid` is a hash of all serialised fields including the scriptSig. A third party can produce a second valid transaction with identical economic effect but a different byte-level encoding of the scriptSig (e.g., by adding extra `OP_0` pushes or changing DER encoding), yielding a different `txid`. If a Bitcoin reorg occurs and the reorganised chain confirms the malleated variant (`tx_id_B`) instead of the original (`tx_id_A`), the BTC light client will accept a Merkle proof for `tx_id_B`. Because `tx_id_B@vout` was never inserted into `verified_deposit_utxo`, the `require!` guard passes and nBTC is minted a second time for the same underlying BTC output.

The bridge accepts raw `tx_bytes` without enforcing SegWit: [5](#0-4) 

No additional binding between the deposit address (which is user-specific via `deposit_msg`) and the `tx_id` is stored, so the deduplication set cannot detect that `tx_id_A` and `tx_id_B` represent the same economic UTXO.

### Impact Explanation

A successful exploit results in two nBTC mints backed by a single BTC deposit — unauthorized minting of nBTC. The recipient specified in `deposit_msg.recipient_id` receives double the nBTC for one BTC, directly inflating the nBTC supply beyond its BTC backing. This matches the **Critical** impact class: *Unauthorized minting of nBTC*.

### Likelihood Explanation

**Low.** The attack requires three simultaneous conditions:
1. The depositor (or a mempool observer) broadcasts a malleated variant of a legacy (non-SegWit) transaction.
2. A Bitcoin reorg of sufficient depth occurs so that the malleated variant is confirmed in the canonical chain while the original is dropped.
3. A relayer (whitelisted via `#[trusted_relayer]`) submits the malleated `tx_bytes` to `verify_deposit_v2`.

Modern wallets default to SegWit outputs, making malleability rare in practice. Deep reorgs on Bitcoin are uncommon. However, the bridge explicitly targets any EVM-compatible or UTXO chain, and Zcash (also supported) has historically experienced deeper reorgs.

### Recommendation

1. **Reject non-SegWit inputs**: In `internal_verify_deposit_entry` and `internal_safe_verify_deposit_entry`, assert that the decoded transaction uses SegWit (i.e., all inputs have witness data). SegWit txids commit only to non-witness fields and are not malleable.
2. **Bind deduplication to the deposit output script**: Supplement the `tx_id`-based key with the deposit address (derived

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L132-143)
```rust
        let transaction = WrappedTransaction::decode(&tx_bytes, &self.internal_config().chain)
            .expect("Deserialization tx_bytes failed");
        let deposit_amount = u128::from(transaction.output()[vout].value.to_sat());
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

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L151-155)
```rust
        let tx_id = transaction.compute_txid().to_string();
        let utxo_storage_key = generate_utxo_storage_key(
            tx_id.clone(),
            u32::try_from(vout).unwrap_or_else(|_| env::panic_str("vout overflow")),
        );
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L369-374)
```rust
        require!(
            self.data_mut()
                .verified_deposit_utxo
                .insert(pending_utxo_info.utxo_storage_key.clone()),
            "Already deposit utxo"
        );
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L396-404)
```rust
        let is_valid = serde_json::from_slice::<bool>(&result_bytes)
            .expect("verify_transaction_inclusion return not bool");
        require!(is_valid, "verify_transaction_inclusion return false");
        require!(
            self.data_mut()
                .verified_deposit_utxo
                .insert(pending_utxo_info.utxo_storage_key.clone()),
            "Already deposit utxo"
        );
```

**File:** contracts/satoshi-bridge/src/utils.rs (L16-23)
```rust
pub fn generate_utxo_storage_key(txid: String, vout: u32) -> String {
    format!(
        "{}{}{}",
        txid,
        UTXO_STORAGE_KEY_TAG,
        vout.to_string().as_str()
    )
}
```
