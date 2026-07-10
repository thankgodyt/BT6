### Title
Hardcoded `BranchId::Nu6_2` in `Transaction::decode` Silently Ignores the `chain` Parameter, Causing Potential Stuck-State for Pre-Nu6_2 Zcash Deposits - (File: contracts/satoshi-bridge/src/zcash_utils/transaction.rs)

### Summary
`zcash_utils/transaction.rs`'s `Transaction::decode()` accepts a `_chain` parameter (note the underscore — it is explicitly unused) but hardcodes `BranchId::Nu6_2` regardless of the configured chain or the actual consensus epoch of the submitted transaction. This is the direct bridge analog of the external report's `_get_new_EC_POINT` issue: a parameter is accepted, silently discarded, and a fixed value is substituted, producing undefined behavior for inputs that do not match the hardcoded assumption. Any user who deposited ZEC during the Nu6 or Nu6_1 consensus period and later calls `request_refund` or `execute_refund` may have their refund permanently blocked.

### Finding Description
In `zcash_utils/transaction.rs`, the `decode` function is defined as:

```rust
pub fn decode(data: &[u8], _chain: &network::Chain) -> Result<Self, std::io::Error> {
    let mut cursor = std::io::Cursor::new(data);
    let branch_id = BranchId::Nu6_2;          // ← hardcoded; _chain is never read
    let tx = ZCashTransaction::read(&mut cursor, branch_id)?;
    Ok(Self { inner_tx: tx })
}
``` [1](#0-0) 

The `_chain` prefix is Rust's explicit signal that the parameter is intentionally unused. The rest of the codebase correctly computes the branch ID from block height via `Chain::get_branch_id()`: [2](#0-1) 

That same logic is used when *constructing* outbound transactions in `to_zcash_tx`: [3](#0-2) 

But `decode()` — used for *inbound* transaction parsing — never consults it.

`decode()` is called in two security-critical refund paths:

1. **`internal_request_refund`** — parses the user-supplied deposit `tx_bytes` to compute the txid and deposit amount: [4](#0-3) 

2. **`refund_execution_inputs`** — re-parses the stored `tx_bytes` to reconstruct the UTXO input for the refund PSBT: [5](#0-4) 

In the Zcash V5 transaction format, the `consensus_branch_id` is a 4-byte field embedded in the serialized bytes. `ZCashTransaction::read()` reads this field and uses the passed `branch_id` to validate or interpret the authorization. If the embedded branch ID in the transaction (e.g., `Nu6` = `0xC2D6D0B4` or `Nu6_1`) does not match the hardcoded `Nu6_2`, the library returns a deserialization error, causing the entire call to fail.

### Impact Explanation
A user who deposited ZEC during the Nu6 or Nu6_1 consensus period holds a deposit transaction whose serialized bytes embed the corresponding branch ID. When that user calls `request_refund`, the contract calls `WrappedTransaction::decode(&tx_bytes.0, &config.chain)` with the hardcoded `Nu6_2`. If the library rejects the mismatch, the call panics/errors, the refund request is never stored, and the user's attached NEAR deposit (anti-spam fee) is consumed. If the user retries `execute_refund` after a request was somehow stored, `refund_execution_inputs` calls `decode()` again and fails identically, leaving the deposit UTXO permanently unspendable by the refund path. The deposit is stuck: it cannot be minted (no `verify_deposit` was called) and cannot be refunded (decode always fails). This matches the **Low/Medium stuck-bridge-state** impact category.

### Likelihood Explanation
The bridge has been live through multiple Zcash consensus upgrades (Nu6 → Nu6_1 → Nu6_2). Any user who deposited ZEC before the Nu6_2 activation height and whose deposit was never finalized via `verify_deposit` is affected. The `request_refund` entry point is publicly callable by any NEAR account with an attached deposit, so no privileged access is required to trigger the failure path.

### Recommendation
Remove the hardcoded `BranchId::Nu6_2` and instead derive the branch ID from the chain and the block height at which the transaction was confirmed, consistent with how `to_zcash_tx` and `Chain::get_branch_id()` already operate. At minimum, pass the `chain` parameter through to a helper that selects the correct branch ID, or attempt decoding with each known branch ID in sequence (Nu6, Nu6_1, Nu6_2) and accept the first success. The `_chain` parameter should be renamed to `chain` and actively used.

### Proof of Concept
1. User deposits ZEC during the Nu6 consensus period (before block 3,146,400 on mainnet). The deposit transaction's serialized bytes embed `BranchId::Nu6` (`0xC2D6D0B4`).
2. The deposit is never finalized via `verify_deposit` (e.g., the relayer missed it).
3. User calls `request_refund(deposit_msg, refund_address, tx_bytes, vout, proof, None)` with the original deposit `tx_bytes`.
4. `internal_request_refund` calls `WrappedTransaction::decode(&tx_bytes.0, &config.chain)`.
5. Inside `decode()`, `branch_id` is hardcoded to `BranchId::Nu6_2`; `_chain` is never read.
6. `ZCashTransaction::read(&mut cursor, BranchId::Nu6_2)` encounters the embedded `Nu6` branch ID and returns a deserialization error.
7. The `expect("Deserialization tx_bytes failed")` panics, the call reverts, the refund request is never stored, and the user's attached NEAR deposit is consumed.
8. The deposit UTXO remains permanently locked: no mint path (no `verify_deposit`) and no refund path (decode always fails with `Nu6_2`). [1](#0-0) [6](#0-5) [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/zcash_utils/transaction.rs (L51-56)
```rust
    pub fn decode(data: &[u8], _chain: &network::Chain) -> Result<Self, std::io::Error> {
        let mut cursor = std::io::Cursor::new(data);
        let branch_id = BranchId::Nu6_2;
        let tx = ZCashTransaction::read(&mut cursor, branch_id)?;
        Ok(Self { inner_tx: tx })
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/transaction.rs (L100-126)
```rust
    pub fn to_zcash_tx(
        vin: &[zcash_transparent::bundle::TxIn<Authorized>],
        vout: &[zcash_transparent::bundle::TxOut],
        input: &[zcash_transparent::bundle::TxOut],
        expiry_height: u32,
        public_keys: &[bitcoin::PublicKey],
        branch_id: BranchId,
    ) -> TransactionData<TransparentUnauthorized> {
        let transparent_bundle = Self::get_transparent_builder(vin, vout, input, public_keys)
            .build()
            .unwrap();

        let lock_time = 0;
        let expiry_height = BlockHeight::from_u32(expiry_height);

        TransactionData::from_parts(
            TxVersion::V5,
            branch_id,
            lock_time,
            expiry_height,
            Some(transparent_bundle),
            None,
            None,
            None,
        )
    }
}
```

**File:** contracts/satoshi-bridge/src/network.rs (L53-66)
```rust
    pub fn get_branch_id(&self, block_height: u32) -> BranchId {
        let block_height_update = BranchIdUpdateBlockHeight::new(self);
        if block_height_update.nu6_2_update != 0 && block_height >= block_height_update.nu6_2_update
        {
            return BranchId::Nu6_2;
        }
        if block_height_update.nu6_1_update != 0 && block_height >= block_height_update.nu6_1_update
        {
            return BranchId::Nu6_1;
        }

        BranchId::Nu6
    }
}
```

**File:** contracts/satoshi-bridge/src/refund.rs (L161-168)
```rust
        let transaction =
            crate::WrappedTransaction::decode(&tx_bytes.0, &self.internal_config().chain)
                .expect("Deserialization tx_bytes failed");
        let tx_id = transaction.compute_txid().to_string();

        let config = self.internal_config();
        let deposit_amount = u128::from(transaction.output()[vout].value.to_sat());
        let confirmations = self.get_confirmations(config, deposit_amount);
```

**File:** contracts/satoshi-bridge/src/refund.rs (L269-278)
```rust
        let transaction =
            crate::WrappedTransaction::decode(&refund_request.tx_bytes.0, &config.chain)
                .expect("Deserialization tx_bytes failed");
        let txid = transaction.compute_txid();
        let outpoint = OutPoint {
            txid,
            vout: u32::try_from(refund_request.vout)
                .unwrap_or_else(|_| env::panic_str("vout overflow")),
        };
        let deposit_output = transaction.output()[refund_request.vout].clone();
```
