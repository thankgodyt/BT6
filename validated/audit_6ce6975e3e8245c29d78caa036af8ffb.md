### Title
Corrupted UTXO Storage via Silent tx_bytes Truncation Causes Permanently Stuck Bridge Funds - (File: contracts/satoshi-bridge/src/btc_light_client/deposit.rs)

### Summary
In `internal_safe_verify_deposit_entry`, when the submitted `tx_bytes` exceeds 10,000 bytes, the actual transaction bytes are silently replaced with 300 zero bytes before the UTXO is stored. The transaction is validated correctly using the original bytes, but the UTXO is persisted with corrupted data. Any subsequent attempt to use this UTXO in a withdrawal will fail when the contract tries to decode the zeroed bytes as a valid transaction, permanently locking those funds in the bridge pool.

### Finding Description
The `internal_safe_verify_deposit_entry` function (invoked from `verify_deposit_v2` when `deposit_msg.safe_deposit.is_some()`) performs correct validation of the deposit transaction — verifying the output amount, script pubkey, and deposit address — using the original `tx_bytes`. However, immediately after validation, the code conditionally replaces the bytes:

```rust
// contracts/satoshi-bridge/src/btc_light_client/deposit.rs lines 204-209
let tx_bytes = if tx_bytes.len() > 10000 {
    env::log_str("tx_bytes length exceeds 10000, truncating to 300 bytes");
    vec![0u8; 300]
} else {
    tx_bytes
};

let utxo = UTXO {
    path,
    tx_bytes,   // ← stored as 300 zero bytes when original > 10000 bytes
    vout,
    balance: transaction.output()[vout].value.to_sat(),
};
```

This is the direct analog to the `timestampAt` vulnerability class: the code uses the **length** of the input data to determine behavior (truncate vs. keep), without validating that the resulting stored value is a well-formed transaction. The validation and the storage operate on different data, breaking the invariant that `utxo.tx_bytes` is a valid serialized transaction for `utxo.vout`.

The corrupted UTXO is then passed through `internal_safe_verify_deposit` → `verify_safe_deposit_callback` → `safe_mint_callback`, where it is added to the bridge's UTXO pool. When a withdrawal later references this UTXO, `WrappedTransaction::decode(&utxo.tx_bytes, ...)` is called on the 300-byte zero buffer, which will fail to parse as a valid transaction and panic, permanently blocking the UTXO from being spent.

### Impact Explanation
The UTXO is permanently stuck in the bridge's pool. The underlying BTC/ZEC is not lost on-chain, but the bridge contract cannot construct or sign a withdrawal transaction spending it. This constitutes a stuck bridge state requiring operator intervention — matching the Medium allowed impact: *"stuck bridge state requiring operator intervention."*

### Likelihood Explanation
Low. A standard deposit transaction (1–2 inputs, 1–2 outputs) is well under 10,000 bytes. However, a Zcash transaction carrying an Orchard bundle can be significantly larger (the codebase itself contains a test transaction whose hex representation is several kilobytes). An attacker who controls the depositing wallet can craft a transaction with many inputs to exceed the threshold, triggering the truncation and locking the resulting UTXO.

### Recommendation
Remove the truncation branch entirely. If on-chain storage cost is a concern, reject oversized `tx_bytes` with an explicit `require!` before any validation, so the deposit call fails cleanly rather than silently corrupting stored state:

```rust
require!(tx_bytes.len() <= 10000, "tx_bytes too large");
```

Alternatively, store only the minimal fields needed for signing (script pubkey, value, vout) rather than the full raw transaction bytes.

### Proof of Concept
1. Craft a Bitcoin/Zcash deposit transaction with > 10,000 bytes (e.g., consolidating many small UTXOs into the bridge deposit address).
2. Call `verify_deposit_v2` with `safe_deposit` set and the oversized `tx_bytes`.
3. The contract validates the transaction correctly (amount, script pubkey match), then stores the UTXO with `tx_bytes = vec![0u8; 300]`.
4. nBTC is minted to the recipient; the UTXO enters the bridge pool.
5. Any subsequent withdrawal attempt referencing this UTXO calls `WrappedTransaction::decode` on the zero buffer, panics, and the UTXO is permanently unspendable. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L171-202)
```rust
    pub(crate) fn internal_safe_verify_deposit_entry(
        &mut self,
        deposit_msg: DepositMsg,
        tx_bytes: Vec<u8>,
        vout: usize,
        tx_block_blockhash: String,
        tx_index: u64,
        merkle_proof: Vec<String>,
        coinbase_proof: Option<(String, Vec<String>)>,
    ) -> Promise {
        require!(
            env::attached_deposit() >= self.required_balance_for_safe_deposit(),
            "Insufficient deposit for storage"
        );

        let path = get_deposit_path(&deposit_msg);
        let safe_deposit_msg = deposit_msg
            .safe_deposit
            .unwrap_or_else(|| env::panic_str("safe_deposit is required in safe_verify_deposit"));

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

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L386-419)
```rust
    #[private]
    pub fn verify_safe_deposit_callback(
        &mut self,
        recipient_id: AccountId,
        mint_amount: U128,
        msg: String,
        pending_utxo_info: PendingUTXOInfo,
    ) -> PromiseOrValue<bool> {
        let result_bytes = env::promise_result_checked(0, MAX_BOOL_RESULT)
            .expect("Call verify_transaction_inclusion failed");
        let is_valid = serde_json::from_slice::<bool>(&result_bytes)
            .expect("verify_transaction_inclusion return not bool");
        require!(is_valid, "verify_transaction_inclusion return false");
        require!(
            self.data_mut()
                .verified_deposit_utxo
                .insert(pending_utxo_info.utxo_storage_key.clone()),
            "Already deposit utxo"
        );

        let msg = (!msg.is_empty())
            .then(|| inject_utxo_id_in_msg(msg, &pending_utxo_info.utxo_storage_key));

        ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
            .with_static_gas(GAS_FOR_MINT_CALL)
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .safe_mint(recipient_id.clone(), mint_amount, msg)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_MINT_CALL_BACK)
                    .safe_mint_callback(recipient_id.clone(), mint_amount, pending_utxo_info),
            )
            .into()
    }
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
