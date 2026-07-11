### Title
Silent tx_bytes Corruption in Safe Deposit Path Permanently Locks BTC UTXOs - (File: contracts/satoshi-bridge/src/btc_light_client/deposit.rs)

### Summary
In `internal_safe_verify_deposit_entry`, when the submitted `tx_bytes` exceed 10,000 bytes, the code silently replaces the real transaction bytes with `vec![0u8; 300]` (300 zero bytes) before storing the UTXO. The deposit amount and tx_id are computed from the original bytes before truncation, so nBTC is minted correctly, but the stored UTXO carries invalid bytes. Any future attempt by the bridge to spend that UTXO — for a withdrawal or refund — will fail to decode the zeroed bytes as a Bitcoin transaction, permanently locking the underlying BTC.

### Finding Description
Inside `internal_safe_verify_deposit_entry`, after the transaction is decoded and the deposit address is verified, the following branch silently corrupts the stored UTXO data:

```rust
let tx_bytes = if tx_bytes.len() > 10000 {
    env::log_str("tx_bytes length exceeds 10000, truncating to 300 bytes");
    vec![0u8; 300]   // ← 300 zero bytes, not a valid Bitcoin transaction
} else {
    tx_bytes
};

let utxo = UTXO {
    path,
    tx_bytes,        // ← zeroed bytes stored here
    vout,
    balance: transaction.output()[vout].value.to_sat(),
};
``` [1](#0-0) 

The `tx_id` and `utxo_storage_key` are derived from the original (real) transaction bytes before the replacement: [2](#0-1) 

So the UTXO is inserted into the bridge's `utxos` map with a correct key and balance but with `tx_bytes = vec![0u8; 300]`. The `safe_mint_callback` then stores this corrupted UTXO via `internal_set_utxo`: [3](#0-2) 

When the bridge later constructs a PSBT for a withdrawal using this UTXO, it calls `WrappedTransaction::decode(&utxo.tx_bytes, ...)`. Decoding 300 zero bytes as a Bitcoin transaction will panic, making the UTXO permanently unspendable. There is no admin function to patch individual UTXO `tx_bytes` in storage; recovery would require a full contract upgrade.

The entry point is `verify_deposit_v2` (with `deposit_msg.safe_deposit = Some(..)`) or the deprecated `safe_verify_deposit`. Both carry `#[trusted_relayer]`, which — as shown by `get_confirmations` — adds extra confirmation requirements for non-whitelisted callers but does **not** block them: [4](#0-3) [5](#0-4) 

### Impact Explanation
The nBTC minted for the deposit is correct and enters circulation. The BTC sits in the bridge's deposit address but can never be spent by the bridge because the stored `tx_bytes` are invalid. This creates a permanent divergence between the nBTC supply and the usable BTC backing: the bridge holds BTC it cannot move, while the corresponding nBTC remains redeemable against other UTXOs. Over time, repeated occurrences drain the pool of spendable UTXOs, eventually causing all withdrawals to fail. This matches the **Medium** impact class: *permanent burning below backed supply / stuck bridge state requiring operator intervention*.

### Likelihood Explanation
A Bitcoin transaction exceeds 10,000 bytes when it consolidates roughly 68+ P2PKH inputs (≈148 bytes each). This is uncommon for a typical single-output deposit but is reachable by any user who sweeps many small UTXOs into one deposit transaction. No special privilege is required beyond submitting a valid BTC transaction and calling `verify_deposit_v2`; non-whitelisted callers simply need more confirmations. The condition can also be triggered accidentally by a legitimate relayer handling an unusually large transaction.

### Recommendation
Remove the silent truncation entirely. If oversized `tx_bytes` must be rejected, do so with an explicit `require!` before any state is mutated, so the call reverts cleanly rather than storing corrupted data:

```rust
require!(
    tx_bytes.0.len() <= MAX_SAFE_DEPOSIT_TX_BYTES,
    "tx_bytes too large for safe deposit"
);
```

If large transactions must be supported, store the full bytes (accepting the storage cost) or store only the specific output fields needed to reconstruct the PSBT input, rather than the entire raw transaction.

### Proof of Concept
1. Construct a Bitcoin transaction with ≥68 P2PKH inputs sending funds to the bridge's deposit address derived from a chosen `DepositMsg`. The transaction will be >10,000 bytes.
2. Wait for the required number of confirmations on the Bitcoin network.
3. Call `verify_deposit_v2(deposit_msg, tx_bytes, vout, proof)` with `deposit_msg.safe_deposit = Some(..)`.
4. The light client verifies the proof; `verify_safe_deposit_callback` fires, mints nBTC to the recipient, and stores the UTXO with `tx_bytes = vec![0u8; 300]`.
5. Attempt any withdrawal that selects this UTXO. The bridge calls `WrappedTransaction::decode(&utxo.tx_bytes, ...)` on the zeroed bytes, which panics. The UTXO is permanently unspendable while the minted nBTC remains in circulation.

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

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L217-221)
```rust
        let tx_id = transaction.compute_txid().to_string();
        let utxo_storage_key = generate_utxo_storage_key(
            tx_id.clone(),
            u32::try_from(vout).unwrap_or_else(|_| env::panic_str("vout overflow")),
        );
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

**File:** contracts/satoshi-bridge/src/config.rs (L321-332)
```rust
    pub fn get_confirmations(&self, config: &Config, satoshi_amount: u128) -> u64 {
        if self
            .data()
            .relayer_white_list
            // Use predecessor_account_id to support both users and proxy protocols.
            .contains(&env::predecessor_account_id())
        {
            config.get_confirmations(satoshi_amount)
        } else {
            config.get_confirmations(satoshi_amount) + u64::from(config.confirmations_delta)
        }
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L70-102)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn verify_deposit_v2(
        &mut self,
        deposit_msg: DepositMsg,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
    ) -> Promise {
        let coinbase_proof = Some((proof.coinbase_tx_id, proof.coinbase_merkle_proof));
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
            self.internal_verify_deposit_entry(
                deposit_msg,
                tx_bytes.0,
                vout,
                proof.tx_block_blockhash,
                proof.tx_index,
                proof.merkle_proof,
                coinbase_proof,
            )
        }
    }
```
