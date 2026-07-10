### Title
P2PKH Refund PSBT Uses Segwit Sighash and Witness, Permanently Locking Deposited Funds on Dogecoin — (`contracts/satoshi-bridge/src/bitcoin_utils/psbt_wrapper.rs`)

---

### Summary

On chains where deposit addresses are P2PKH (Dogecoin, Dogecoin Testnet), `internal_execute_refund` builds a refund PSBT whose `witness_utxo` is the P2PKH deposit output. `get_hash_to_sign` then unconditionally calls `p2wpkh_signature_hash` on that P2PKH `script_pubkey`, computing a BIP143 segwit sighash instead of the required legacy sighash. `save_signature` unconditionally writes the result into `final_script_witness` instead of `final_script_sig`. The resulting transaction is structurally invalid and can never confirm on-chain. Because `finalize_refund_with_psbt` inserts the UTXO into `verified_deposit_utxo` synchronously during `execute_refund` — before any signing or broadcast — the deposit UTXO is permanently blocked from both refund and `verify_deposit`, destroying the user's funds.

---

### Finding Description

**Step 1 — Deposit address type on Dogecoin**

`generate_utxo_chain_address` calls `Address::from_pubkey` with the configured chain. For Dogecoin, `get_segwit_hrp` returns `None`, so `from_pubkey` falls through to the `Address::P2pkh` branch. Every Dogecoin deposit address is therefore P2PKH. [1](#0-0) [2](#0-1) 

**Step 2 — `internal_execute_refund` sets P2PKH output as `witness_utxo`**

`refund_execution_inputs` decodes the original deposit transaction and extracts `deposit_output` — a `TxOut` whose `script_pubkey` is a P2PKH script. `set_input_utxo` stores this directly as `psbt.inputs[i].witness_utxo`. [3](#0-2) [4](#0-3) 

**Step 3 — `get_hash_to_sign` unconditionally uses `p2wpkh_signature_hash`**

Regardless of the `script_pubkey` type stored in `witness_utxo`, `get_hash_to_sign` always calls `SighashCache::p2wpkh_signature_hash`. For a P2PKH `script_pubkey` this computes a BIP143 segwit sighash using the P2PKH script as the script_code — a completely different value from the legacy sighash that a P2PKH verifier requires. [5](#0-4) 

**Step 4 — `save_signature` unconditionally writes a witness**

After signing, `save_signature` sets `final_script_witness` via `Witness::p2wpkh`. P2PKH inputs require a `script_sig` containing the DER signature and compressed public key; a witness field is ignored by legacy verifiers. The transaction is therefore doubly invalid: wrong sighash and wrong signature placement. [6](#0-5) 

**Step 5 — `verified_deposit_utxo` is marked before signing**

`finalize_refund_with_psbt` inserts the UTXO key into `verified_deposit_utxo` synchronously during `execute_refund`, before any signing or broadcast occurs. This blocks any future `verify_deposit` for the same UTXO. [7](#0-6) 

**Step 6 — Re-execution cannot recover**

`load_refund_request_for_execute` permits re-execution when `refund_request.executed == true`. However, the PSBT is built deterministically from the same inputs and outputs, producing the same txid. `finalize_refund_with_psbt` would panic at `"pending info already exist"` for the same txid. The old `BTCPendingInfo` cannot be removed via `internal_remove_refund_pending_tx_id` while the refund request is still active. `reject_refund` (DAO/Operator only) can remove the request but does not clear `verified_deposit_utxo`, so `verify_deposit` remains blocked. [8](#0-7) [9](#0-8) 

**Step 7 — `execute_refund` is publicly callable**

`execute_refund` carries no `#[trusted_relayer]` or `#[access_control_any]` guard at the method level. `resolve_execute_refund_timelock` explicitly handles unprivileged callers by applying a longer timelock, confirming the function is reachable by any account after the timelock elapses. [10](#0-9) [11](#0-10) 

---

### Impact Explanation

Any user who deposits DOGE to a bridge-generated P2PKH address and whose refund request reaches `execute_refund` will have their funds permanently destroyed. The deposit UTXO is simultaneously blocked from `verify_deposit` (by `verified_deposit_utxo`) and from a valid refund (by the invalid transaction). There is no on-chain recovery path available to the user. This is a **Critical** impact: significant permanent loss of user funds.

---

### Likelihood Explanation

Dogecoin is an explicitly supported chain in the codebase (`Chain::DogecoinMainnet`, `Chain::DogecoinTestnet`). Every Dogecoin deposit address is P2PKH by construction. Any refund on Dogecoin triggers this path. The bug is systematic, not a corner case.

---

### Recommendation

`get_hash_to_sign` must branch on the `script_pubkey` type of `witness_utxo`:
- If `script_pubkey.is_p2wpkh()` → use `p2wpkh_signature_hash` (BIP143) and set `final_script_witness`.
- If `script_pubkey.is_p2pkh()` → use `legacy_signature_hash` (BIP143 legacy) and set `final_script_sig` with the DER-encoded signature and public key.

Similarly, `save_signature` must write to `final_script_sig` for P2PKH inputs instead of `final_script_witness`.

Additionally, `verified_deposit_utxo` should not be marked until the refund transaction is confirmed on-chain (i.e., in `verify_refund_finalize_callback`), or at minimum the marking should be rolled back if signing fails.

---

### Proof of Concept

```
Chain: DogecoinMainnet
1. User deposits 1 DOGE to bridge P2PKH address (generated by generate_utxo_chain_address).
2. User calls request_refund with tx_bytes, vout, proof → stored in refund_requests.
3. After unsafe_refund_timelock_sec, user calls execute_refund(utxo_storage_key, None).
4. internal_execute_refund:
   - deposit_output.script_pubkey = OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG (P2PKH)
   - psbt.inputs[0].witness_utxo = deposit_output  ← P2PKH TxOut
   - finalize_refund_with_psbt → verified_deposit_utxo.insert(key)  ← UTXO locked
5. sign_btc_transaction → get_hash_to_sign:
   - p2wpkh_signature_hash(0, &P2PKH_script, value, All)  ← BIP143 sighash, WRONG
6. sign_btc_transaction_callback → save_signature:
   - final_script_witness = Witness::p2wpkh(...)  ← witness on P2PKH input, WRONG
7. Transaction broadcast → rejected by Dogecoin network (invalid sighash + no script_sig).
8. verify_deposit(utxo_storage_key) → panics: "Already deposit utxo"
9. execute_refund again → finalize_refund_with_psbt panics: "pending info already exist"
10. User's 1 DOGE is permanently lost.

Assert: get_hash_to_sign on a P2PKH witness_utxo produces a BIP143 hash ≠ legacy sighash.
Assert: verified_deposit_utxo contains the key after execute_refund, before any broadcast.
```

### Citations

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

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L25-43)
```rust
        let RefundExecutionInputs {
            outpoint,
            deposit_output,
            refund_amount,
        } = self.refund_execution_inputs(&refund_request);
        let refund_output = self.build_refund_output(&refund_request.refund_address, refund_amount);

        let mut psbt = PsbtWrapper::new(vec![outpoint], vec![refund_output]);
        psbt.set_input_utxo(vec![deposit_output]);

        let caller = env::predecessor_account_id();
        self.finalize_refund_with_psbt(
            caller,
            refund_request,
            psbt,
            refund_amount,
            utxo_storage_key,
        );
        PromiseOrValue::Value(())
```

**File:** contracts/satoshi-bridge/src/bitcoin_utils/psbt_wrapper.rs (L75-80)
```rust
    pub fn set_input_utxo(&mut self, input_utxo: Vec<TxOut>) {
        input_utxo
            .iter()
            .enumerate()
            .for_each(|(i, v)| self.psbt.inputs[i].witness_utxo = Some(v.clone()));
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

**File:** contracts/satoshi-bridge/src/bitcoin_utils/psbt_wrapper.rs (L156-164)
```rust
    pub fn save_signature(
        &mut self,
        sign_index: usize,
        signature: SignatureResponse,
        public_key: bitcoin::secp256k1::PublicKey,
    ) {
        self.psbt.inputs[sign_index].final_script_witness =
            Some(Witness::p2wpkh(&signature.to_btc_signature(), &public_key));
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L201-228)
```rust
    pub(crate) fn resolve_execute_refund_timelock(&self, utxo_storage_key: &str) -> u64 {
        require!(
            env::attached_deposit() >= self.required_balance_for_execute_refund(),
            "Insufficient deposit for storage"
        );
        let caller = env::predecessor_account_id();
        let is_privileged =
            self.acl_has_any_role(vec![Role::DAO.into(), Role::RefundOperator.into()], caller);
        let refund_request: RefundRequest = self
            .data()
            .refund_requests
            .get(utxo_storage_key)
            .expect("Refund request not found")
            .into();
        let config = self.internal_config();
        if refund_request.deposit_msg().refund_address.is_some() {
            // Pre-authorized refund address: privileged users can fast-track.
            if is_privileged {
                0
            } else {
                config.refund_timelock_sec
            }
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L250-261)
```rust
        // Block only if the UTXO was claimed by a deposit. If it was claimed by
        // our own refund (executed == true, which also set verified_deposit_utxo),
        // re-running execute_refund is allowed — re-creating the refund tx, e.g.
        // after a consensus branch change.
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );

        refund_request
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L366-372)
```rust
        require!(
            self.data_mut()
                .btc_pending_infos
                .insert(btc_pending_id.clone(), btc_pending_info.into())
                .is_none(),
            "pending info already exist"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L377-380)
```rust
        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L581-589)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn execute_refund(
        &mut self,
        utxo_storage_key: String,
        chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
        self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
    }
```
