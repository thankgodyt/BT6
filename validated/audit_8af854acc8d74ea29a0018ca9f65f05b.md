### Title
Hardcoded `BranchId::Nu6_2` in `Transaction::decode` Causes Wrong Txid Computation for Pre-Nu6_2 Deposits, Permanently Blocking Refunds — (File: `contracts/satoshi-bridge/src/zcash_utils/transaction.rs`)

---

### Summary

`Transaction::decode` hardcodes `BranchId::Nu6_2` regardless of when the Zcash transaction was actually created. For Zcash V5 transactions (ZIP-244), the transaction ID is computed using the consensus branch ID as an input to the hash. A transaction created before the Nu6_2 activation block has a real on-chain txid computed with `Nu6_1` (or `Nu6`). Decoding it with `Nu6_2` produces a different txid, causing the bridge's light-client verification call to fail with a txid that does not exist in the Zcash blockchain. Any user who deposited ZEC before Nu6_2 activation and whose deposit was never finalized cannot request a refund — their ZEC is permanently locked in the bridge's deposit address.

---

### Finding Description

In `contracts/satoshi-bridge/src/zcash_utils/transaction.rs`, the `decode` function ignores the `_chain` parameter and hardcodes the consensus branch:

```rust
pub fn decode(data: &[u8], _chain: &network::Chain) -> Result<Self, std::io::Error> {
    let mut cursor = std::io::Cursor::new(data);
    let branch_id = BranchId::Nu6_2;   // ← always Nu6_2, chain ignored
    let tx = ZCashTransaction::read(&mut cursor, branch_id)?;
    Ok(Self { inner_tx: tx })
}
``` [1](#0-0) 

The `_chain` parameter is never consulted. The activation heights for Nu6_2 are block 3,364,600 on mainnet and block 4,052,000 on testnet: [2](#0-1) 

By contrast, every *construction* path correctly derives the branch ID dynamically:

```rust
fn get_branch_id(current_height: u32, config: &Config) -> BranchId {
    config.chain.get_branch_id(current_height)
}
``` [3](#0-2) 

The refund path calls `WrappedTransaction::decode` to compute the txid that is then forwarded to the light client for inclusion verification:

```rust
let transaction =
    crate::WrappedTransaction::decode(&tx_bytes.0, &self.internal_config().chain)
        .expect("Deserialization tx_bytes failed");
let tx_id = transaction.compute_txid().to_string();
// ...
self.verify_transaction_inclusion_promise(
    config.btc_light_client_account_id.clone(),
    tx_id,   // ← wrong txid for pre-Nu6_2 deposits
    ...
)
``` [4](#0-3) 

Because Zcash V5 txids are branch-ID-dependent (ZIP-244 uses the consensus branch ID as a domain separator in the transaction hash), the txid computed with `Nu6_2` for a transaction that was broadcast under `Nu6_1` differs from the real on-chain txid. The light client holds the real txid; the bridge submits the wrong one; verification returns `false` and the callback panics or reverts.

The same decode call is repeated inside `request_refund_callback`: [5](#0-4) 

---

### Impact Explanation

A user who sent ZEC to the bridge's deposit address before block 3,364,600 (mainnet) and whose deposit was never finalized (e.g., the relayer never submitted a proof, or the proof was rejected) has no recovery path:

- `request_refund` computes the wrong txid → light-client verification fails → the refund request is never stored.
- The deposit UTXO remains in the bridge's custody address on the Zcash network with no on-chain mechanism to reclaim it.
- This constitutes **permanent, irrecoverable loss of user ZEC**.

This matches the allowed impact: *"Critical. Zcash-specific validation failure that enables … permanent loss."*

---

### Likelihood Explanation

Nu6_2 activated on Zcash mainnet at block 3,364,600. Any deposit transaction confirmed before that block carries a `Nu6_1` (or `Nu6`) branch ID in its txid. The bridge has been operational across this upgrade window. Any such unfinalized deposit is permanently unrefundable. The entry path is fully unprivileged: any NEAR account can call `request_refund` with their own deposit transaction bytes.

---

### Recommendation

Replace the hardcoded branch ID in `Transaction::decode` with a dynamic lookup that mirrors the construction path. Because the raw transaction bytes do not encode the branch ID, the caller must supply the block height at which the transaction was confirmed (available from the light client or from the proof metadata) and derive the branch ID from it:

```rust
pub fn decode(data: &[u8], chain: &network::Chain, confirmed_height: u32) -> Result<Self, std::io::Error> {
    let mut cursor = std::io::Cursor::new(data);
    let branch_id = chain.get_branch_id(confirmed_height);
    let tx = ZCashTransaction::read(&mut cursor, branch_id)?;
    Ok(Self { inner_tx: tx })
}
```

Alternatively, if the confirmed height is unavailable, try decoding with each known branch ID in reverse chronological order and accept the first that succeeds, then verify the resulting txid against the proof-supplied txid before proceeding.

---

### Proof of Concept

1. User deposits ZEC at block 3,000,000 (mainnet, Nu6_1 era). The deposit transaction's real txid is `T_real` (computed with `Nu6_1`).
2. The relayer never submits a deposit proof (or the proof is rejected). The user calls `request_refund` with the raw `tx_bytes`.
3. `WrappedTransaction::decode(&tx_bytes, chain)` calls `Transaction::decode` with hardcoded `Nu6_2`, computing txid `T_wrong ≠ T_real`.
4. `verify_transaction_inclusion_promise(…, T_wrong, …)` is dispatched to the light client.
5. The light client has no record of `T_wrong`; it returns `false`.
6. `request_refund_callback` receives `false`, hits `require!(is_valid, …)`, and reverts.
7. No `RefundRequest` is ever stored. The user cannot retry with a different txid because the txid is derived deterministically from `tx_bytes`. The ZEC is permanently locked.

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

**File:** contracts/satoshi-bridge/src/network.rs (L39-49)
```rust
            Chain::ZcashMainnet => Self {
                nu6_1_update: 3146400,
                nu6_2_update: 3364600,
            },
            Chain::ZcashTestnet => Self {
                nu6_1_update: 3536500,
                nu6_2_update: 4052000,
            },
            _ => unreachable!(),
        }
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L543-545)
```rust
fn get_branch_id(current_height: u32, config: &Config) -> BranchId {
    config.chain.get_branch_id(current_height)
}
```

**File:** contracts/satoshi-bridge/src/refund.rs (L161-183)
```rust
        let transaction =
            crate::WrappedTransaction::decode(&tx_bytes.0, &self.internal_config().chain)
                .expect("Deserialization tx_bytes failed");
        let tx_id = transaction.compute_txid().to_string();

        let config = self.internal_config();
        let deposit_amount = u128::from(transaction.output()[vout].value.to_sat());
        let confirmations = self.get_confirmations(config, deposit_amount);

        self.verify_transaction_inclusion_promise(
            config.btc_light_client_account_id.clone(),
            tx_id,
            proof.tx_block_blockhash,
            proof.tx_index,
            proof.merkle_proof,
            Some((proof.coinbase_tx_id, proof.coinbase_merkle_proof)),
            confirmations,
        )
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_FOR_REQUEST_REFUND_CALLBACK)
                .request_refund_callback(deposit_msg, refund_address, tx_bytes, vout, gas_fee),
        )
```

**File:** contracts/satoshi-bridge/src/refund.rs (L511-528)
```rust
        let config = self.internal_config();
        let transaction = crate::WrappedTransaction::decode(&tx_bytes.0, &config.chain)
            .expect("Deserialization tx_bytes failed");
        let output = &transaction.output()[vout];

        // Verify that the output script matches the deposit address derived from deposit_msg
        let path = get_deposit_path(&deposit_msg);
        let deposit_address = self.generate_utxo_chain_address(&path);
        let deposit_script_pubkey = deposit_address
            .script_pubkey()
            .expect("Invalid deposit address");
        require!(
            deposit_script_pubkey == output.script_pubkey,
            "Output script_pubkey does not match deposit address"
        );

        let amount = u128::from(output.value.to_sat());
        let tx_id = transaction.compute_txid().to_string();
```
