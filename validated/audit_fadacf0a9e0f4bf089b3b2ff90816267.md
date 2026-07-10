### Title
Silent tx_bytes Corruption in `internal_safe_verify_deposit_entry` Permanently Locks Bridge UTXOs - (File: contracts/satoshi-bridge/src/btc_light_client/deposit.rs)

### Summary
In `internal_safe_verify_deposit_entry`, when the submitted `tx_bytes` exceed 10,000 bytes, the code silently replaces them with 300 zero bytes (`vec![0u8; 300]`) instead of rejecting the call. This corrupted byte array is then stored verbatim in the UTXO struct and persisted to the bridge's UTXO pool. Any subsequent attempt to use that UTXO — for a withdrawal, active UTXO management, or refund — will fail because decoding 300 zero bytes as a Bitcoin transaction is impossible. The BTC locked in that UTXO becomes permanently inaccessible.

### Finding Description
The stub replacement occurs at lines 204–209 of `deposit.rs`:

```rust
let tx_bytes = if tx_bytes.len() > 10000 {
    env::log_str("tx_bytes length exceeds 10000, truncating to 300 bytes");
    vec![0u8; 300]   // ← not a truncation; replaces real bytes with zeros
} else {
    tx_bytes
};
``` [1](#0-0) 

The comment says "truncating" but the implementation produces 300 zero bytes — a placeholder stub, not a truncation. The UTXO is then constructed with this corrupted payload:

```rust
let utxo = UTXO {
    path,
    tx_bytes,   // ← zeroed bytes when original > 10 000 bytes
    vout,
    balance: transaction.output()[vout].value.to_sat(),
};
``` [2](#0-1) 

The deposit address and balance are validated against the **original** decoded transaction (lines 195–202), so those checks pass. But the UTXO stored in the pool carries the zeroed `tx_bytes`. Every downstream operation that must reconstruct the Bitcoin transaction from `utxo.tx_bytes` — PSBT construction for withdrawals, active UTXO management, and refund execution — will call `WrappedTransaction::decode(&utxo.tx_bytes, ...)` and panic on the all-zero payload. [3](#0-2) 

This path is reached via `safe_verify_deposit` / `verify_deposit_v2` (with `safe_deposit = Some(..)`): [4](#0-3) 

The analogous production path `internal_verify_deposit_entry` has **no such truncation**, confirming this is an unintended stub left in the safe-deposit branch. [5](#0-4) 

### Impact Explanation
Once the corrupted UTXO is inserted into `data.utxos` via `safe_mint_callback → internal_set_utxo`, the BTC it represents is permanently locked:

- Withdrawal PSBT construction decodes `utxo.tx_bytes` to build the input witness; decoding 300 zero bytes panics, blocking the withdrawal.
- Active UTXO management (`active_utxo_management`) follows the same decode path and fails identically.
- The operator has no on-chain recovery path: every method that touches this UTXO requires decoding its `tx_bytes`.

nBTC is minted to the user (the mint call succeeds because balance and script checks use the pre-truncation decoded transaction), but the backing BTC UTXO is permanently inaccessible. This breaks the 1:1 backing invariant and constitutes permanent locking of protocol funds.

**Allowed impact match:** *Medium — stuck bridge state requiring operator intervention* / *Critical — significant permanent locking of user or protocol funds.*

### Likelihood Explanation
A Bitcoin transaction exceeds 10,000 bytes when it consolidates roughly 50+ P2WPKH inputs or 30+ P2PKH inputs — unusual but entirely valid on-chain. A user who sweeps many small UTXOs into a single deposit transaction, or a consolidation transaction routed through the bridge, can reach this threshold without any malicious intent. The trusted relayer has no reason to reject a valid, confirmed Bitcoin transaction; it simply submits the proof as normal, triggering the bug transparently.

### Recommendation
Replace the silent stub with an explicit rejection:

```rust
require!(
    tx_bytes.len() <= MAX_SAFE_DEPOSIT_TX_BYTES,
    "tx_bytes too large for safe deposit"
);
```

Define `MAX_SAFE_DEPOSIT_TX_BYTES` at a value that fits within gas limits (consistent with `MAX_REQUEST_REFUND_TX_BYTES = 200_000` used in the refund path). Never silently replace caller-supplied data with a zero-filled placeholder in a production code path.

### Proof of Concept

1. User consolidates 60 P2WPKH UTXOs into a single output sent to their bridge deposit address. The resulting transaction is ~11,000 bytes — valid on Bitcoin, confirmed in a block.
2. Trusted relayer calls `verify_deposit_v2` with `deposit_msg.safe_deposit = Some(..)` and the 11,000-byte `tx_bytes`.
3. `internal_safe_verify_deposit_entry` decodes the transaction, verifies the output script and balance (passes), then replaces `tx_bytes` with `vec![0u8; 300]`.
4. Light-client verification succeeds; `safe_mint_callback` mints nBTC to the user and calls `internal_set_utxo` with the zeroed UTXO.
5. User later initiates a withdrawal via `ft_transfer_call`. The bridge selects the corrupted UTXO; `WrappedTransaction::decode(&[0u8; 300], ...)` panics. The withdrawal fails permanently.
6. The BTC locked in that UTXO is irrecoverable on-chain. The user holds nBTC with no redeemable backing. [1](#0-0) [6](#0-5)

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L117-169)
```rust
    pub(crate) fn internal_verify_deposit_entry(
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
            deposit_msg.safe_deposit.is_none(),
            "safe_deposit not supported in verify_deposit"
        );
        let path = get_deposit_path(&deposit_msg);
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

        let utxo = UTXO {
            path,
            tx_bytes,
            vout,
            balance: transaction.output()[vout].value.to_sat(),
        };
        let tx_id = transaction.compute_txid().to_string();
        let utxo_storage_key = generate_utxo_storage_key(
            tx_id.clone(),
            u32::try_from(vout).unwrap_or_else(|_| env::panic_str("vout overflow")),
        );
        self.internal_verify_deposit(
            deposit_amount,
            tx_block_blockhash,
            tx_index,
            merkle_proof,
            coinbase_proof,
            PendingUTXOInfo {
                tx_id,
                utxo_storage_key,
                utxo,
            },
            deposit_msg,
        )
    }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L171-237)
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
        let tx_id = transaction.compute_txid().to_string();
        let utxo_storage_key = generate_utxo_storage_key(
            tx_id.clone(),
            u32::try_from(vout).unwrap_or_else(|_| env::panic_str("vout overflow")),
        );

        self.internal_safe_verify_deposit(
            deposit_amount,
            tx_block_blockhash,
            tx_index,
            merkle_proof,
            coinbase_proof,
            PendingUTXOInfo {
                tx_id,
                utxo_storage_key,
                utxo,
            },
            deposit_msg.recipient_id,
            safe_deposit_msg,
        )
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L81-101)
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
```
