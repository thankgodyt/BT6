### Title
Silent `tx_bytes` Zeroing in Safe Deposit Path Permanently Locks Bridge UTXOs — (File: `contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

---

### Summary

When a Bitcoin transaction submitted via the safe-deposit path of `verify_deposit_v2` has `tx_bytes` exceeding 10,000 bytes, the bridge silently replaces the raw transaction bytes with 300 zero bytes before storing the resulting UTXO. The deposit amount is correctly extracted and nBTC is minted, but the stored UTXO carries invalid (all-zero) transaction bytes that can never be decoded or spent. The backing BTC is permanently locked in the bridge's deposit address and the UTXO is permanently stuck in the bridge's available set.

---

### Finding Description

In `internal_safe_verify_deposit_entry`, after the deposit amount is extracted from the real transaction and the `tx_id` is computed, the following block silently corrupts the stored UTXO data:

```rust
// contracts/satoshi-bridge/src/btc_light_client/deposit.rs  lines 204-209
let tx_bytes = if tx_bytes.len() > 10000 {
    env::log_str("tx_bytes length exceeds 10000, truncating to 300 bytes");
    vec![0u8; 300]
} else {
    tx_bytes
};
``` [1](#0-0) 

The UTXO is then constructed and stored with these zeroed bytes:

```rust
let utxo = UTXO {
    path,
    tx_bytes,   // ← 300 zero bytes when original > 10 000 bytes
    vout,
    balance: transaction.output()[vout].value.to_sat(),
};
``` [2](#0-1) 

The `tx_id` and `utxo_storage_key` are computed from the **original** (real) transaction before the replacement, so the UTXO is keyed correctly and inserted into `verified_deposit_utxo` and the UTXO storage. The deposit proof passes, nBTC is minted, and the UTXO appears healthy in the bridge's set.

Later, when the bridge attempts to construct a withdrawal spending this UTXO, it calls:

```rust
WrappedTransaction::decode(tx_bytes, &config.chain)
```

on the 300-byte zero buffer. This will panic or return an error, making the UTXO permanently unspendable. The backing BTC is locked in the on-chain deposit address forever, and the UTXO slot is permanently occupied in the bridge's available set.

The entry point is `verify_deposit_v2` with `deposit_msg.safe_deposit = Some(...)`:

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
``` [3](#0-2) 

The `#[trusted_relayer]` macro adjusts the required confirmation count for non-whitelisted callers (via `confirmations_delta`) but does **not** gate access — any NEAR account can call this function. [4](#0-3) 

---

### Impact Explanation

The backing BTC is permanently locked in the bridge's deposit address on Bitcoin. The bridge holds a UTXO record with a correct balance and key but with undecodable transaction bytes, so it can never be selected for a withdrawal. This permanently reduces the bridge's spendable UTXO pool. If repeated, an attacker can progressively drain the bridge's withdrawal liquidity without recovering the deposited BTC themselves. This matches the allowed Medium impact: **attacker-triggered permanent locking of bridged funds**.

---

### Likelihood Explanation

A Bitcoin transaction exceeds 10,000 bytes when it has roughly 67 or more P2WPKH inputs (~148 vbytes each). An attacker who has accumulated many small UTXOs on Bitcoin (e.g., from prior small deposits or dust) can craft such a transaction. The safe-deposit path is reachable by any NEAR account that can supply a valid Merkle proof for a confirmed Bitcoin transaction. No privileged role is required.

---

### Recommendation

Replace the silent zeroing with a hard rejection:

```rust
require!(
    tx_bytes.len() <= 10_000,
    "tx_bytes exceeds maximum allowed length"
);
```

If very large transactions must be supported, store only the minimal data needed to identify the UTXO (txid + vout + value) rather than the full raw bytes, and reconstruct or fetch the full transaction only when signing.

---

### Proof of Concept

1. Attacker accumulates ≥70 small Bitcoin UTXOs under their control.
2. Attacker constructs a Bitcoin transaction with those 70+ inputs, with one output paying the bridge's safe-deposit address (derived from a `DepositMsg` with `safe_deposit = Some(...)`). The serialized transaction exceeds 10,000 bytes.
3. The transaction is confirmed on Bitcoin; the attacker obtains a valid Merkle proof.
4. Attacker calls `verify_deposit_v2` on the bridge with `deposit_msg.safe_deposit = Some(...)`, the large `tx_bytes`, and the valid proof.
5. Bridge extracts `deposit_amount` and `tx_id` from the real transaction — both correct.
6. Bridge hits the `tx_bytes.len() > 10000` branch and replaces `tx_bytes` with `vec![0u8; 300]`.
7. UTXO is stored with zeroed `tx_bytes` but correct `balance` and `utxo_storage_key`.
8. Light-client proof passes; `verify_safe_deposit_callback` fires; nBTC is minted to the attacker.
9. The UTXO now sits permanently in the bridge's UTXO set. Any future withdrawal attempt that selects it calls `WrappedTransaction::decode(&[0u8; 300], ...)`, which panics, leaving the BTC permanently locked. [5](#0-4)

### Citations

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L70-79)
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
