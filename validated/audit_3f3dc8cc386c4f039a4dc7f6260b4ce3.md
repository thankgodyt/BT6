### Title
Silent `tx_bytes` Corruption in `internal_safe_verify_deposit_entry` Permanently Locks Oversized-Transaction UTXOs - (File: `contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

### Summary

When a safe deposit is submitted with a Bitcoin transaction larger than 10,000 bytes, `internal_safe_verify_deposit_entry` silently replaces the real transaction bytes with 300 zero bytes (`vec![0u8; 300]`) before storing the UTXO in the bridge's pool. The deposit is accepted and nBTC is minted, but the stored UTXO carries corrupted `tx_bytes`. Any subsequent withdrawal that selects this UTXO will fail at PSBT construction because the previous-transaction data cannot be decoded, permanently locking the corresponding BTC in the bridge.

### Finding Description

In `internal_safe_verify_deposit_entry`, after the deposit transaction is decoded and validated, the following block executes before the UTXO is stored:

```rust
let tx_bytes = if tx_bytes.len() > 10000 {
    env::log_str("tx_bytes length exceeds 10000, truncating to 300 bytes");
    vec![0u8; 300]          // ← not a truncation; replaces with 300 zero bytes
} else {
    tx_bytes
};
``` [1](#0-0) 

The comment says "truncating," but the code does not truncate — it replaces the entire byte array with 300 null bytes. This corrupted value is then placed into the `UTXO` struct:

```rust
let utxo = UTXO {
    path,
    tx_bytes,          // ← now vec![0u8; 300]
    vout,
    balance: transaction.output()[vout].value.to_sat(),
};
``` [2](#0-1) 

This UTXO is then inserted into the bridge's live UTXO pool via `internal_set_utxo`. When a withdrawal later calls `generate_vutxos` and selects this UTXO, the PSBT pipeline must decode `tx_bytes` to supply the previous-transaction data required for signing. Decoding 300 zero bytes as a Bitcoin transaction will panic or return an error, making the UTXO permanently unspendable through the normal withdrawal path. [3](#0-2) 

There is no admin function in the bridge API that allows updating or replacing the `tx_bytes` field of an already-stored UTXO, so the corruption cannot be remediated on-chain.

### Impact Explanation

The BTC deposited via a large safe-deposit transaction is permanently locked inside the bridge contract. The bridge holds the UTXO (it received the BTC and minted nBTC), but it cannot construct a valid PSBT to spend that UTXO in any future withdrawal or active UTXO management operation. This constitutes a **permanent loss of protocol-controlled funds** matching the allowed impact: *"Significant loss, theft, destruction, or permanent locking of user or protocol funds."*

### Likelihood Explanation

A Bitcoin transaction exceeds 10,000 bytes when it consolidates roughly 67+ P2PKH inputs (~148 bytes each) or fewer SegWit inputs. This is uncommon for ordinary users but is a realistic scenario for:

- DApps or custodians that aggregate many small UTXOs into a single deposit.
- Automated relayers submitting consolidation transactions through the safe-deposit path.

The `safe_deposit` path is explicitly designed for DApp integrations (e.g., Omni Bridge), which are more likely to submit programmatically constructed transactions that could be large. No attacker action is required; any legitimate user with a large deposit transaction triggers the bug.

### Recommendation

Replace the silent corruption with an explicit rejection:

```rust
require!(
    tx_bytes.len() <= MAX_SAFE_DEPOSIT_TX_BYTES,
    "tx_bytes too large for safe deposit"
);
```

If storage cost is the concern, the bridge should either (a) reject oversized transactions outright, or (b) store only the specific output being deposited (value + script) rather than the full `tx_bytes`, provided the PSBT pipeline can be adapted to use witness-UTXO data instead of the full previous transaction.

### Proof of Concept

1. User has 70 small UTXOs and constructs a single Bitcoin transaction spending all of them into the bridge's safe-deposit address. The transaction is ~10,360 bytes.
2. Relayer calls `verify_deposit_v2` with `deposit_msg.safe_deposit = Some(..)` and the large `tx_bytes`.
3. `internal_safe_verify_deposit_entry` decodes the transaction successfully, verifies the output script matches the deposit address, and passes light-client verification.
4. The `tx_bytes.len() > 10000` branch fires; `tx_bytes` is replaced with `vec![0u8; 300]`.
5. The UTXO is stored in the bridge pool with `tx_bytes = [0u8; 300]`. nBTC is minted to the user.
6. Later, an operator initiates a withdrawal that selects this UTXO. `generate_vutxos` reads the UTXO and passes `tx_bytes` to the PSBT builder.
7. The PSBT builder attempts `WrappedTransaction::decode(&utxo.tx_bytes, &chain)` on 300 zero bytes — this fails/panics.
8. The withdrawal cannot proceed. The BTC is permanently locked; no on-chain path exists to repair the stored `tx_bytes`. [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L191-221)
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
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L79-98)
```rust
        let (utxo_storage_keys, vutxos) = self.generate_vutxos(&mut psbt);
        let max_pending = self.get_max_pending_sign_txs(&sender_id);
        let account = self.internal_unwrap_or_create_mut_account(&sender_id);
        require!(
            account.pending_sign_count() < max_pending,
            "Too many pending sign transactions"
        );

        let withdraw_change_address_script_pubkey =
            self.internal_config().get_change_script_pubkey();
        let withdraw_fee = self.internal_config().withdraw_bridge_fee.get_fee(amount);
        let (actual_received_amount, gas_fee) = self.check_withdraw_psbt_valid(
            target_btc_address.clone(),
            &withdraw_change_address_script_pubkey,
            &psbt,
            &vutxos,
            amount,
            withdraw_fee,
            max_gas_fee,
        );
```
