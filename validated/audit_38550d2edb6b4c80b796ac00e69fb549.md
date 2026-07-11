### Title
Corrupted UTXO `tx_bytes` via Hardcoded 10 000-byte Truncation Permanently Locks Deposited Funds - (File: contracts/satoshi-bridge/src/btc_light_client/deposit.rs)

### Summary

`internal_safe_verify_deposit_entry` silently replaces the caller-supplied `tx_bytes` with 300 zero bytes whenever the raw transaction exceeds 10 000 bytes. The corrupted bytes are then persisted inside the `UTXO` struct. Every subsequent attempt to decode those bytes — required to build and sign the spending transaction — panics, permanently locking the deposited BTC/ZEC in the bridge's MPC-controlled address while the corresponding nBTC/nZEC remains in circulation.

### Finding Description

In `internal_safe_verify_deposit_entry`, after the deposit transaction is successfully decoded and validated, a size guard silently overwrites `tx_bytes`:

```rust
let tx_bytes = if tx_bytes.len() > 10000 {
    env::log_str("tx_bytes length exceeds 10000, truncating to 300 bytes");
    vec![0u8; 300]   // ← 300 zero bytes replace the real transaction
} else {
    tx_bytes
};

let utxo = UTXO {
    path,
    tx_bytes,        // ← corrupted bytes stored permanently
    vout,
    balance: transaction.output()[vout].value.to_sat(),
};
``` [1](#0-0) 

The `UTXO` struct persists `tx_bytes` verbatim in on-chain storage: [2](#0-1) 

Later, every code path that needs to spend the UTXO calls `WrappedTransaction::decode` on the stored bytes. For Bitcoin: [3](#0-2) 

For Zcash: [4](#0-3) 

Decoding 300 zero bytes as a Bitcoin or Zcash transaction will always fail, causing an `expect`-triggered panic. The same panic occurs in the withdrawal burn callback, which also re-decodes `tx_bytes_with_sign` from the pending info: [5](#0-4) 

The `generate_vutxos` call inside `create_active_utxo_management_pending_info` passes a mutable PSBT reference, indicating it populates the PSBT's input-UTXO fields (needed for MPC signing) directly from the stored `tx_bytes`: [6](#0-5) 

For Zcash, `get_hash_to_sign` reads `inputs_utxo[vin].script_pubkey()` and `inputs_utxo[vin].value()`, which are populated from the stored UTXO data: [7](#0-6) 

### Impact Explanation

A depositor whose on-chain transaction exceeds 10 000 bytes (achievable with ≥ ~68 P2PKH inputs, a realistic consolidation transaction) calls `safe_verify_deposit`. The bridge:

1. Successfully verifies the deposit via the light client.
2. Mints nBTC/nZEC to the depositor.
3. Stores the UTXO with `tx_bytes = vec![0u8; 300]`.

From this point the UTXO is permanently unspendable: every withdrawal, active UTXO management, or RBF attempt that touches this UTXO panics on `WrappedTransaction::decode`. The deposited BTC/ZEC is locked in the bridge's MPC address forever, while the minted nBTC/nZEC remains in circulation unbacked by spendable collateral. This breaks the 1:1 backing invariant and constitutes permanent loss of protocol funds.

### Likelihood Explanation

Bitcoin transactions with many inputs routinely exceed 10 000 bytes. A consolidation transaction with 68 P2PKH inputs (~148 bytes each) already crosses the threshold. Any user who deposits via such a transaction and uses `safe_verify_deposit` (which requires an attached NEAR deposit for storage) triggers the bug. No privileged access is required; the entry point is fully public.

### Recommendation

Remove the truncation entirely. If on-chain storage cost is a concern, reject oversized transactions with an explicit `require!` rather than silently corrupting the data:

```rust
require!(
    tx_bytes.len() <= MAX_SAFE_DEPOSIT_TX_BYTES,
    "tx_bytes too large for safe_verify_deposit"
);
```

This mirrors the approach already used in `internal_request_refund`: [8](#0-7) 

### Proof of Concept

1. Construct a Bitcoin transaction with ≥ 68 P2PKH inputs paying the bridge deposit address. Serialized size will exceed 10 000 bytes.
2. Call `safe_verify_deposit` with valid Merkle proof and the large `tx_bytes`, attaching the required NEAR storage deposit.
3. The bridge verifies the deposit, mints nBTC, and stores `UTXO { tx_bytes: vec![0u8; 300], balance: <real_amount>, … }`.
4. Attempt any withdrawal that references this UTXO's `OutPoint`. The bridge calls `WrappedTransaction::decode(&[0u8; 300], chain)`, which returns `Err`, and the subsequent `.expect("Deserialization tx_bytes failed")` panics, reverting the transaction.
5. The UTXO remains in storage permanently unspendable; the deposited BTC is locked forever.

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L204-215)
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

**File:** contracts/satoshi-bridge/src/zcash_utils/transaction.rs (L51-56)
```rust
    pub fn decode(data: &[u8], _chain: &network::Chain) -> Result<Self, std::io::Error> {
        let mut cursor = std::io::Cursor::new(data);
        let branch_id = BranchId::Nu6_2;
        let tx = ZCashTransaction::read(&mut cursor, branch_id)?;
        Ok(Self { inner_tx: tx })
    }
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L79-81)
```rust
            let tx_bytes = btc_pending_info.tx_bytes_with_sign.as_ref().unwrap();
            let transaction = WrappedTransaction::decode(tx_bytes, &self.internal_config().chain)
                .expect("Deserialization tx_bytes failed");
```

**File:** contracts/satoshi-bridge/src/btc_light_client/active_utxo_management.rs (L74-76)
```rust
        let (utxo_storage_keys, vutxos) = self.generate_vutxos(&mut psbt);
        let (actual_received_amount, gas_fee) =
            self.check_active_management_psbt_valid(&psbt, &vutxos);
```

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L466-477)
```rust
        let script = self.inputs_utxo[vin].script_pubkey();
        let transparent_bundle = tx_data.transparent_bundle().unwrap_or_else(|| {
            env::panic_str("ERR_NO_TRANSPARENT_BUNDLE: missing transparent bundle")
        });
        let sig_input = zcash_primitives::transaction::sighash::SignableInput::Transparent(
            zcash_transparent::sighash::SignableInput::from_parts(
                transparent_bundle,
                SighashType::ALL,
                vin,
                script,
                script,
                self.inputs_utxo[vin].value(),
```

**File:** contracts/satoshi-bridge/src/refund.rs (L150-153)
```rust
        require!(
            tx_bytes.0.len() <= MAX_REQUEST_REFUND_TX_BYTES,
            "tx_bytes too large for refund request"
        );
```
