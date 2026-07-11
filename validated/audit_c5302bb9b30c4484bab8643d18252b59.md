### Title
Zero-Value `inputs_utxo` in Zcash Withdrawal PSBT Sighash Causes All Withdrawal Transactions to Produce Invalid Signatures — (`contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs`)

---

### Summary

`PsbtWrapper::new` initializes `inputs_utxo` to all-zero `ZcashTxOut` entries. `set_input_utxo` is only ever called in the refund path. For every Zcash withdrawal PSBT, `get_hash_to_sign` therefore computes the ZIP-244 sighash using zero as the input value and an empty script as the input script. The Zcash network verifies signatures against the actual UTXO values from its UTXO set; the resulting mismatch makes every withdrawal signature invalid, so every withdrawal transaction is rejected on-chain. Users who burn nZEC to initiate a withdrawal have their tokens destroyed while the underlying ZEC remains permanently locked in the bridge UTXO.

---

### Finding Description

**Initialization — always zero for withdrawals**

In `PsbtWrapper::new`, `inputs_utxo` is explicitly set to a vector of zero-value, empty-script `ZcashTxOut` entries: [1](#0-0) 

```rust
let inputs =
    vec![ZcashTxOut::new(Zatoshis::from_u64(0).unwrap(), Script::default()); vin.len()];
```

**`set_input_utxo` is only called in the refund path**

The only call site that populates `inputs_utxo` with real UTXO data is `execute_refund_callback`: [2](#0-1) 

For withdrawals (`ft_on_transfer_callback`) and all RBF variants (`from_original_psbt`, which carries over the original zero `inputs_utxo`), `set_input_utxo` is never called: [3](#0-2) [4](#0-3) 

**`get_hash_to_sign` uses the zero value directly in the ZIP-244 sighash** [5](#0-4) 

Both the `script` (line 466) and the `value` (line 477) fed to `SignableInput::from_parts` come from `self.inputs_utxo[vin]`, which is zero/empty for every withdrawal.

**`WrappedTransaction::to_zcash_tx` also receives the zero `inputs_utxo`** [6](#0-5) 

The `input` slice passed to `get_transparent_builder` is `&self.inputs_utxo`, so the `TransparentInputInfo` objects embedded in the unsigned transaction also carry zero values: [7](#0-6) 

---

### Impact Explanation

Zcash v5 transactions use the ZIP-244 sighash algorithm, which commits to all transparent input values via an `amounts_sig_digest`. A signature produced over a sighash that encodes zero input values is cryptographically bound to that zero-value context. When the Zcash network verifies the transaction it looks up the actual UTXO values from its UTXO set, recomputes the sighash with those real values, and the signature does not match — the transaction is rejected.

Every Zcash withdrawal therefore follows this path:
1. User burns nZEC (irreversible).
2. Bridge constructs a PSBT with zero `inputs_utxo`.
3. MPC chain-signatures service signs the incorrect (zero-value) sighash.
4. Bridge broadcasts the transaction.
5. Zcash network rejects it (invalid signature).
6. ZEC remains locked in the bridge UTXO; nZEC is already destroyed.

This constitutes **permanent locking of user funds** — Critical impact under "Significant loss, theft, destruction, or permanent locking of user or protocol funds."

**Regarding the specific replay/malleability claim in the question:** the claimed attack — replaying a zero-value signature to authorize spending of a different UTXO — is **not achievable**. The ZIP-244 sighash also commits to the specific `prevout` (txid + vout index), the outputs hash, and the expiry height, so a signature produced for one PSBT cannot be replayed against a different UTXO. The actual impact is the simpler and more severe one: all withdrawal signatures are invalid on the Zcash network.

---

### Likelihood Explanation

This is a systemic, unconditional bug. No attacker action is required; every Zcash withdrawal PSBT is affected. Any user who initiates a withdrawal triggers it. The only mitigating factor is whether the bridge is currently live on Zcash mainnet; if it is, every withdrawal attempt fails.

---

### Recommendation

In `ft_on_transfer_callback` (and `active_utxo_management_callback`), after constructing the PSBT, look up the actual UTXO values for each input from on-chain state and call `psbt.set_input_utxo(...)` before the PSBT is stored. The refund path already demonstrates the correct pattern:

```rust
// refund.rs — correct pattern
let mut psbt = PsbtWrapper::new(...);
psbt.set_input_utxo(vec![deposit_output]);  // ← must be replicated for withdrawals
```

For withdrawals the bridge already tracks the UTXOs being spent (they are the bridge's own UTXOs); their `TxOut` values must be fetched from storage and passed to `set_input_utxo` before the PSBT is serialized and stored in `BTCPendingInfo`.

---

### Proof of Concept

```rust
// Construct a withdrawal PSBT exactly as ft_on_transfer_callback does
let psbt = PsbtWrapper::new(
    vec![outpoint],          // real bridge UTXO
    vec![recipient_output],  // withdrawal output
    None,                    // no Orchard bundle
    expiry_height,
    current_height,
    Some(target_address),
    &config,
);

// inputs_utxo[0].value() == 0  ← confirmed by PsbtWrapper::new line 74-75
let hash = psbt.get_hash_to_sign(0, &public_keys);

// The MPC service signs `hash`.
// The Zcash network recomputes the sighash using the real UTXO value (e.g. 1_000_000 zatoshis).
// The two hashes differ → signature verification fails → transaction rejected.
// nZEC already burned; ZEC permanently locked.
assert_eq!(psbt.inputs_utxo[0].value().into_u64(), 0); // always true for withdrawals
```

### Citations

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L74-75)
```rust
        let inputs =
            vec![ZcashTxOut::new(Zatoshis::from_u64(0).unwrap(), Script::default()); vin.len()];
```

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L140-148)
```rust
        Self {
            branch_id: get_branch_id(current_height, config),
            expiry_height,
            vin: original_psbt.vin,
            vout,
            inputs_utxo: original_psbt.inputs_utxo,
            orchard,
            recipient_address: original_psbt.recipient_address,
        }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L454-484)
```rust
    pub fn get_hash_to_sign(&self, vin: usize, public_keys: &[bitcoin::PublicKey]) -> [u8; 32] {
        let tx_data = WrappedTransaction::to_zcash_tx(
            &self.vin,
            &self.vout,
            &self.inputs_utxo,
            self.expiry_height,
            public_keys,
            self.branch_id,
        );
        let txid_parts =
            self.tx_digest(&tx_data, zcash_primitives::transaction::txid::TxIdDigester);

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
            )
            .unwrap_or_else(|_| env::panic_str("ERR_SIGNABLE_INPUT: invalid input index")),
        );

        *zcash_primitives::transaction::sighash::signature_hash(&tx_data, &sig_input, &txid_parts)
            .as_ref()
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/refund.rs (L107-116)
```rust
        let mut psbt = PsbtWrapper::new(
            vec![outpoint],
            output,
            orchard_bundle,
            expiry_height,
            last_block_height,
            Some(refund_request.refund_address.clone()),
            self.internal_config(),
        );
        psbt.set_input_utxo(vec![deposit_output]);
```

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L124-134)
```rust
        let psbt = PsbtWrapper::new(
            input,
            output,
            orchard_bundle,
            expiry_height,
            last_block_height,
            Some(target_btc_address.clone()),
            self.internal_config(),
        );

        self.create_btc_pending_info(sender_id, amount.0, target_btc_address, psbt, max_gas_fee);
```

**File:** contracts/satoshi-bridge/src/zcash_utils/transaction.rs (L66-75)
```rust
        for index in 0..vin.len() {
            let input_info = TransparentInputInfo::from_parts(
                vin[index].prevout().clone(),
                input[index].clone(),
                SpendInfo::P2pkh {
                    pubkey: public_keys[index].inner,
                },
            )
            .unwrap();
            builder.add_input(input_info);
```
