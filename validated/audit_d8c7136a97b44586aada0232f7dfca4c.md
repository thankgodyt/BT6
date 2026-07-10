### Title
Hardcoded `p2wpkh_signature_hash` in `get_hash_to_sign` Causes Permanent UTXO Locking on Dogecoin (P2PKH) Deployments — (`contracts/satoshi-bridge/src/bitcoin_utils/psbt_wrapper.rs`)

---

### Summary

`PsbtWrapper::get_hash_to_sign` in `bitcoin_utils/psbt_wrapper.rs` unconditionally calls `p2wpkh_signature_hash` (BIP143 SegWit sighash) regardless of the actual script type of the UTXO being spent. For chains where `get_segwit_hrp` returns `None` (Dogecoin), `generate_utxo_chain_address` produces P2PKH addresses, so every bridge-controlled UTXO has a P2PKH `script_pubkey`. Calling `p2wpkh_signature_hash` on a P2PKH script causes the `bitcoin` crate to return `Err(P2wpkhError::NotP2wpkhScript)`, which the `.expect(...)` turns into a NEAR panic. Every call to `sign_btc_transaction` for a Dogecoin UTXO panics, permanently locking those UTXOs in the pending-sign state with no recovery path.

The Zcash half of the question's premise is **incorrect**: when the `zcash` feature is compiled in, `lib.rs` routes to `zcash_utils::psbt_wrapper`, which has its own `get_hash_to_sign` using the correct Zcash transparent sighash algorithm. Zcash is not affected.

---

### Finding Description

**Feature-flag dispatch** (`lib.rs`):

```
#[cfg(not(feature = "zcash"))]  → bitcoin_utils::psbt_wrapper  (used for BTC, Dogecoin, Litecoin)
#[cfg(feature = "zcash")]       → zcash_utils::psbt_wrapper    (used for Zcash only)
``` [1](#0-0) [2](#0-1) 

**Address generation for Dogecoin** — `get_segwit_hrp` returns `None` for Dogecoin, so `Address::from_pubkey` falls into the `else` branch and creates `Address::P2pkh`: [3](#0-2) [4](#0-3) 

**`generate_vutxos`** sets `witness_utxo` with the P2PKH `script_pubkey` derived from `generate_utxo_chain_address`: [5](#0-4) 

**`get_hash_to_sign`** unconditionally calls `p2wpkh_signature_hash` on whatever `script_pubkey` is stored in `witness_utxo`: [6](#0-5) 

In the `bitcoin` crate (0.31+), `p2wpkh_signature_hash` calls `script_pubkey.p2wpkh_script_code()` internally and returns `Err(P2wpkhError::NotP2wpkhScript)` for any non-P2WPKH script. The `.expect("ERR_SIGHASH: failed to compute signature hash")` panics.

**`sign_btc_transaction`** is a public, unpermissioned entry point (only paused by DAO, no `trusted_relayer` guard): [7](#0-6) 

It calls `internal_sign_btc_transaction`, which calls `get_hash_to_sign`: [8](#0-7) 

---

### Impact Explanation

When a Dogecoin deployment processes a withdrawal:

1. `ft_on_transfer` → `create_btc_pending_info` → `generate_vutxos` removes the UTXOs from the bridge's available set and stores a `BTCPendingInfo` with `PendingInfoStage::PendingSign`. This transaction **succeeds**.
2. Any subsequent call to `sign_btc_transaction` panics inside `get_hash_to_sign`. The NEAR transaction fails and rolls back — but the `BTCPendingInfo` (created in step 1) is **not** rolled back; it persists.
3. The UTXOs are no longer in the available UTXO set and cannot be re-added. The pending-sign record cannot be completed (signing always panics). There is no admin function to cancel a pending-sign record or return UTXOs to the available set.

Result: **permanent locking** of all bridge-controlled Dogecoin UTXOs involved in any withdrawal attempt.

---

### Likelihood Explanation

This triggers on the first withdrawal attempt for any Dogecoin UTXO. No special attacker input is required — the normal user withdrawal flow (`ft_on_transfer` with a valid Dogecoin UTXO) is sufficient. The bug is deterministic and 100% reproducible for every Dogecoin P2PKH UTXO.

---

### Recommendation

In `get_hash_to_sign`, branch on the actual script type of `witness_utxo.script_pubkey`:

- If `script_pubkey.is_p2wpkh()` → use `p2wpkh_signature_hash` (BIP143 SegWit path, correct for Bitcoin/Litecoin).
- If `script_pubkey.is_p2pkh()` → use `legacy_signature_hash` (pre-SegWit path, correct for Dogecoin).
- Reject any other script type explicitly.

Additionally, `save_signature` must also branch: P2PKH inputs require the signature in `script_sig` (via `final_script_sig`), not in `final_script_witness` (which `Witness::p2wpkh` produces).

---

### Proof of Concept

```
1. Deploy bridge with Chain::DogecoinMainnet (no `zcash` feature).
2. Deposit DOGE to the bridge's P2PKH deposit address.
3. Call verify_deposit → UTXO added to bridge set with P2PKH script_pubkey.
4. Call nbtc.ft_transfer(bridge, amount, WithdrawMsg { input: [utxo], output: [...] })
   → ft_on_transfer → create_btc_pending_info → generate_vutxos sets witness_utxo
     with P2PKH script_pubkey → BTCPendingInfo created (PendingSign stage).
5. Call sign_btc_transaction(btc_pending_sign_id, 0, 0)
   → internal_sign_btc_transaction
   → get_hash_to_sign
   → p2wpkh_signature_hash(&p2pkh_script_pubkey, ...)
   → Err(P2wpkhError::NotP2wpkhScript)
   → .expect() panics: "ERR_SIGHASH: failed to compute signature hash"
6. NEAR tx fails; BTCPendingInfo remains in PendingSign state permanently.
7. UTXO is no longer in the available set and cannot be recovered.
```

### Citations

**File:** contracts/satoshi-bridge/src/lib.rs (L21-24)
```rust
#[cfg(not(feature = "zcash"))]
pub mod bitcoin_utils;
#[cfg(feature = "zcash")]
pub mod zcash_utils;
```

**File:** contracts/satoshi-bridge/src/lib.rs (L63-66)
```rust
#[cfg(not(feature = "zcash"))]
pub use crate::bitcoin_utils::psbt_wrapper;
#[cfg(not(feature = "zcash"))]
pub use crate::bitcoin_utils::transaction::Transaction as WrappedTransaction;
```

**File:** contracts/satoshi-bridge/src/network.rs (L259-278)
```rust
    pub fn from_pubkey(chain: Chain, pubkey: bitcoin::PublicKey) -> Result<Self, String> {
        let pubkey_hash = pubkey.pubkey_hash();

        if let Some(_hrp) = get_segwit_hrp(&chain) {
            // Chain supports Bech32 SegWit
            let wp = WitnessProgram::p2wpkh(
                &pubkey
                    .try_into()
                    .map_err(|e| format!("Error on converting pubkey to bytes: {e}"))?,
            );
            let wp = WitnessProgram::new(WitnessVersion::V0, wp.program().as_bytes())
                .map_err(|e| format!("bech32 guarantees valid program length for witness: {e}"))?;
            Ok(Address::Segwit { program: wp, chain })
        } else {
            // Legacy P2PKH
            Ok(Address::P2pkh {
                hash: pubkey_hash,
                chain,
            })
        }
```

**File:** contracts/satoshi-bridge/src/network.rs (L351-366)
```rust
pub fn get_segwit_hrp(chain: &Chain) -> Option<&'static str> {
    match chain {
        // Bitcoin (Bech32 - BIP173)
        Chain::BitcoinMainnet => Some("bc"),
        Chain::BitcoinTestnet => Some("tb"),

        // Litecoin (Bech32)
        Chain::LitecoinMainnet => Some("ltc"),
        Chain::LitecoinTestnet => Some("tltc"),

        // Zcash (Bech32m) support unified addresses with hrp but not segwit
        Chain::ZcashMainnet | Chain::ZcashTestnet => None,

        // Dogecoin (no native Bech32 support yet)
        Chain::DogecoinMainnet | Chain::DogecoinTestnet => None,
    }
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L266-283)
```rust
    pub fn generate_vutxos(&mut self, psbt: &mut PsbtWrapper) -> (Vec<String>, Vec<VUTXO>) {
        let (utxo_storage_keys, vutxos) = self.remove_vutxo_by_psbt(psbt);

        let input_utxo = vutxos
            .iter()
            .map(|v| TxOut {
                value: Amount::from_sat(v.get_amount()),
                script_pubkey: self
                    .generate_utxo_chain_address(&v.get_path())
                    .script_pubkey()
                    .expect("Invalid address"),
            })
            .collect();

        psbt.set_input_utxo(input_utxo);

        (utxo_storage_keys, vutxos)
    }
```

**File:** contracts/satoshi-bridge/src/bitcoin_utils/psbt_wrapper.rs (L137-154)
```rust
    pub fn get_hash_to_sign(&self, vin: usize, public_keys: &[bitcoin::PublicKey]) -> [u8; 32] {
        let tx = self.psbt.unsigned_tx.clone();
        let mut cache = SighashCache::new(tx);
        let witness_utxo = self.psbt.inputs[vin]
            .witness_utxo
            .as_ref()
            .expect("ERR_MISSING_WITNESS_UTXO: input missing witness UTXO data");
        cache
            .p2wpkh_signature_hash(
                vin,
                &witness_utxo.script_pubkey,
                witness_utxo.value,
                bitcoin::EcdsaSighashType::All,
            )
            .expect("ERR_SIGHASH: failed to compute signature hash")
            .to_raw_hash()
            .to_byte_array()
    }
```

**File:** contracts/satoshi-bridge/src/api/chain_signatures.rs (L19-43)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_btc_transaction(
        &mut self,
        btc_pending_sign_id: String,
        sign_index: usize,
        key_version: u32,
    ) -> PromiseOrValue<bool> {
        let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);
        btc_pending_info.assert_pending_sign();
        if let Some(original_tx_id) = btc_pending_info.get_original_tx_id() {
            if !self.check_btc_pending_info_exists(original_tx_id) {
                require!(
                    self.internal_unwrap_mut_account(&btc_pending_info.account_id.clone())
                        .btc_pending_sign_ids
                        .remove(&btc_pending_sign_id),
                    "Internal error"
                );
                self.internal_remove_btc_pending_info(&btc_pending_sign_id);
                return PromiseOrValue::Value(true);
            }
        }
        self.internal_sign_btc_transaction(btc_pending_sign_id, sign_index, key_version)
            .into()
    }
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L76-113)
```rust
    pub fn internal_sign_btc_transaction(
        &mut self,
        btc_pending_sign_id: String,
        sign_index: usize,
        key_version: u32,
    ) -> Promise {
        let pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);

        let public_keys: Vec<_> = pending_info
            .vutxos
            .iter()
            .map(|vutxo| self.generate_btc_public_key(&vutxo.get_path()))
            .collect();

        let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);
        require!(
            btc_pending_info.signatures[sign_index].is_none(),
            "Already signed"
        );
        let payload = btc_pending_info
            .get_psbt()
            .get_hash_to_sign(sign_index, &public_keys);
        let path = btc_pending_info.vutxos[sign_index].get_path();
        self.sign_promise(SignRequest {
            payload,
            path,
            key_version,
        })
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_FOR_SIGN_BTC_TRANSACTION_CALL_BACK)
                .sign_btc_transaction_callback(
                    btc_pending_info.account_id.clone(),
                    btc_pending_sign_id,
                    sign_index,
                ),
        )
    }
```
