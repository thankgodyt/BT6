### Title
Corrupted `tx_bytes` Stored in UTXO via Incorrect Length Truncation Permanently Locks Deposited Funds - (File: contracts/satoshi-bridge/src/btc_light_client/deposit.rs)

### Summary

`internal_safe_verify_deposit_entry` contains a faulty length guard that, instead of rejecting an oversized transaction, silently replaces the raw transaction bytes with 300 zero bytes before storing the UTXO. Any UTXO registered through this path with a transaction larger than 10 000 bytes will have permanently corrupted `tx_bytes` in contract storage, making the UTXO unusable for withdrawal and locking the deposited funds.

### Finding Description

In `internal_safe_verify_deposit_entry`, after the transaction is successfully decoded and validated, the following block executes:

```rust
let tx_bytes = if tx_bytes.len() > 10000 {
    env::log_str("tx_bytes length exceeds 10000, truncating to 300 bytes");
    vec![0u8; 300]          // ← 300 zero bytes, not a truncation
} else {
    tx_bytes
};
``` [1](#0-0) 

The comment says "truncating", but the code does not truncate — it replaces the entire byte vector with 300 null bytes. The UTXO is then constructed with this corrupted payload:

```rust
let utxo = UTXO {
    path,
    tx_bytes,          // ← 300 zero bytes
    vout,
    balance: transaction.output()[vout].value.to_sat(),
};
``` [2](#0-1) 

The UTXO is persisted to contract state via `internal_set_utxo` in `safe_mint_callback`: [3](#0-2) 

The `UTXO` struct stores `tx_bytes` as a first-class field: [4](#0-3) 

During withdrawal, `BTCPendingInfo::get_psbt()` calls `PsbtWrapper::deserialize`, and the signing path calls `get_hash_to_sign`, which requires the `inputs_utxo` to be populated from the decoded `tx_bytes`. When `WrappedTransaction::decode` is called on 300 zero bytes, it panics: [5](#0-4) 

The regular deposit path (`internal_verify_deposit_entry`) does not contain this truncation and stores the original `tx_bytes` correctly: [6](#0-5) 

### Impact Explanation

Any UTXO registered via `safe_verify_deposit` whose underlying BTC transaction exceeds 10 000 bytes will be stored with corrupted `tx_bytes`. The `balance` field is correct (funds are credited), but the UTXO can never be spent by the bridge: every subsequent attempt to build or sign a withdrawal PSBT using that UTXO will panic on `WrappedTransaction::decode`. The deposited BTC is permanently locked inside the bridge's UTXO set with no automated recovery path. This matches the **Medium** impact class: stuck bridge state requiring operator intervention, with the additional risk of permanent loss if no privileged recovery mechanism exists.

### Likelihood Explanation

Bitcoin transactions exceeding 10 000 bytes are uncommon but entirely valid — a consolidation transaction with ~65+ P2WPKH inputs reaches this threshold. A relayer submitting a proof for such a transaction via `safe_verify_deposit` (a public, permissionless call requiring only a storage deposit) will silently trigger the corruption. No special privileges are required; any honest relayer processing a large real-world deposit can inadvertently trigger it.

### Recommendation

Replace the silent replacement with an explicit rejection:

```rust
require!(
    tx_bytes.len() <= 10000,
    "tx_bytes length exceeds 10000 bytes"
);
```

If large transactions must be supported, store the original `tx_bytes` unchanged and raise the limit, or store only the relevant `TxOut` (value + script_pubkey at `vout`) rather than the full raw transaction.

### Proof of Concept

1. Construct a valid Bitcoin transaction with ≥ 65 P2WPKH inputs (raw size > 10 000 bytes) that sends funds to the bridge deposit address.
2. Call `safe_verify_deposit` with the valid Merkle proof and the large `tx_bytes`.
3. The bridge decodes and validates the transaction successfully (lines 191–202), mints nBTC to the recipient, but stores `UTXO { tx_bytes: vec![0u8; 300], balance: <correct>, … }`.
4. Attempt any withdrawal that selects this UTXO as an input. The call to `WrappedTransaction::decode(&utxo.tx_bytes, …)` panics with "Deserialization tx_bytes failed", permanently blocking withdrawal of those funds. [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L145-150)
```rust
        let utxo = UTXO {
            path,
            tx_bytes,
            vout,
            balance: transaction.output()[vout].value.to_sat(),
        };
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L191-209)
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

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L437-437)
```rust
            self.internal_set_utxo(&pending_utxo_info.utxo_storage_key, pending_utxo_info.utxo);
```

**File:** contracts/satoshi-bridge/src/utxo.rs (L9-15)
```rust
pub struct UTXO {
    pub path: String,
    pub tx_bytes: Vec<u8>,
    pub vout: usize,
    #[serde(with = "u64_dec_format")]
    pub balance: u64,
}
```

**File:** contracts/satoshi-bridge/src/bitcoin_utils/transaction.rs (L29-36)
```rust
    pub fn decode(
        data: &[u8],
        _chain: &network::Chain,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let mut cursor = bitcoin::io::Cursor::new(data);
        let tx = BtcTransaction::consensus_decode(&mut cursor)?;
        Ok(Self { inner_tx: tx })
    }
```
