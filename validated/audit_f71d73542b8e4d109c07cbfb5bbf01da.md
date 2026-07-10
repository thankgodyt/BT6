### Title
Missing Caller Authentication in `sign_btc_transaction` Enables Attacker to Inject Invalid Signature and Permanently Lock Funds — (`contracts/satoshi-bridge/src/api/chain_signatures.rs`)

---

### Summary

`sign_btc_transaction` is a public, payable function with no check that the caller owns the pending transaction. Any unprivileged account can call it on any `btc_pending_sign_id` with an arbitrary `key_version`. Because the "Already signed" guard is evaluated **before** the async MPC sign call is dispatched, two concurrent sign calls for the same `(pending_id, sign_index)` can both pass the guard and both fire. The first callback to land writes its signature unconditionally; the second panics and rolls back. An attacker who submits first with a wrong `key_version` writes a signature produced by a different MPC key into the PSBT. The callback re-derives the public key from the path alone (ignoring `key_version`), so the stored witness pairs a valid-looking public key with a signature from a mismatched key. When all inputs are "signed", the contract finalises the transaction and moves it to `PendingVerify`. The resulting Bitcoin transaction is cryptographically invalid and will be rejected by every Bitcoin node, while the UTXOs were already removed from the contract's UTXO set at pending-info creation time — permanently locking the funds.

---

### Finding Description

**Root cause — no caller authentication:** [1](#0-0) 

`sign_btc_transaction` loads `btc_pending_info` and checks only that the stage is `PendingSign`. There is no `require!(env::predecessor_account_id() == btc_pending_info.account_id, "Unauthorized")` guard. Any account can call this function on any pending ID.

**Pre-async "Already signed" check — race window:** [2](#0-1) 

The guard `signatures[sign_index].is_none()` is evaluated synchronously, before the MPC sign promise is dispatched. If two transactions targeting the same `(pending_id, sign_index)` are processed in the same block, both pass this check and both fire a sign call. The signature slot is not reserved/locked between the check and the callback.

**Attacker-controlled `key_version` forwarded verbatim to MPC:** [3](#0-2) 

`key_version` is passed directly to the chain-signatures contract with no validation against the expected version for the UTXO path.

**Callback re-derives public key from path only — ignores `key_version`:** [4](#0-3) 

`generate_btc_public_key` uses only the derivation path. If the MPC contract signed with a different key version, the returned signature is from a different key, but the callback pairs it with the path-derived public key — producing an invalid P2WPKH witness.

**No signature validity check before writing:** [5](#0-4) 

`save_signature` blindly constructs `Witness::p2wpkh(signature, public_key)` without verifying that the signature was actually produced by the corresponding private key.

**Irreversible finalisation on `is_all_signed()`:** [6](#0-5) 

Once all `signatures` slots are `Some`, `extract_tx_bytes_with_sign()` is called, `tx_bytes_with_sign` is set, and the state transitions to `PendingVerify`. There is no rollback path if the resulting Bitcoin transaction is invalid.

**UTXOs removed at pending-info creation — no recovery:** [7](#0-6) 

UTXOs are consumed (`UtxoRemoved` event, removed from the UTXO set) when the pending info is created. If the finalised transaction is invalid and can never confirm, those UTXOs are gone from the contract's perspective with no recovery mechanism.

---

### Impact Explanation

An attacker who injects an invalid signature for even one input of a multi-input transaction causes the entire Bitcoin transaction to be unbroadcastable. The contract has already consumed the UTXOs and moved the pending info to `PendingVerify`. The Bitcoin transaction will be rejected by every node. The funds are permanently locked: the contract no longer tracks the UTXOs as spendable, and the invalid transaction can never confirm.

---

### Likelihood Explanation

- `btc_pending_sign_id` values are public contract state, observable by any account.
- The attacker only needs to submit their `sign_btc_transaction` call in an earlier block (or earlier in the same block) than the legitimate relayer.
- The NEAR chain-signatures protocol documents `key_version` as a versioning field; using a non-zero value that the MPC network does not recognise causes the sign call to fail (callback returns `false`, no write). However, if the MPC network supports even one additional key version, the attack is fully exploitable. The parameter's existence in the public API surface makes this a realistic assumption for any production or near-future deployment.
- No special role, leaked key, or privileged access is required.

---

### Recommendation

1. **Add caller authentication** at the top of `sign_btc_transaction`:
   ```rust
   require!(
       env::predecessor_account_id() == btc_pending_info.account_id,
       "Unauthorized: caller is not the transaction owner"
   );
   ```
2. **Reserve the signature slot atomically** before dispatching the async call (e.g., write a sentinel `Some(placeholder)` before the promise and replace it in the callback), or use a per-input in-flight lock, to close the pre-async race window.
3. **Validate `key_version`** against a contract-configured expected version before forwarding to the MPC contract.
4. **Verify the returned signature** against the expected public key in `sign_btc_transaction_callback` before writing it to the PSBT.

---

### Proof of Concept

```
Block N:
  Attacker calls: sign_btc_transaction(victim_pending_id, sign_index=0, key_version=1)
    → assert_pending_sign() passes
    → no caller check
    → signatures[0].is_none() == true → passes
    → MPC sign call dispatched with key_version=1

Block N (same block, later receipt):
  Legitimate relayer calls: sign_btc_transaction(victim_pending_id, sign_index=0, key_version=0)
    → signatures[0].is_none() == true (async call still in flight) → passes
    → MPC sign call dispatched with key_version=0

Block N+1 (attacker's callback arrives first):
  sign_btc_transaction_callback(account_id, victim_pending_id, sign_index=0)
    → signatures[0].is_none() == true
    → signature from key_version=1 written to signatures[0]
    → psbt.save_signature(0, sig_from_key1, pubkey_from_path)
      → Witness::p2wpkh(sig_from_key1, pubkey_from_key0) — INVALID WITNESS

Block N+1 (legitimate callback arrives second):
  sign_btc_transaction_callback(...)
    → signatures[0].is_none() == false
    → require! panics → state rolled back

[If this was the last unsigned input]:
  is_all_signed() == true
  extract_tx_bytes_with_sign() → invalid Bitcoin tx
  tx_bytes_with_sign = Some(invalid_tx)
  to_pending_verify_stage()
  btc_pending_sign_ids.remove(victim_pending_id)

Result:
  - UTXOs already removed from contract UTXO set (at pending-info creation)
  - Invalid Bitcoin tx can never confirm
  - Funds permanently locked
```

### Citations

**File:** contracts/satoshi-bridge/src/api/chain_signatures.rs (L21-43)
```rust
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

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L91-94)
```rust
        require!(
            btc_pending_info.signatures[sign_index].is_none(),
            "Already signed"
        );
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L99-103)
```rust
        self.sign_promise(SignRequest {
            payload,
            path,
            key_version,
        })
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L145-152)
```rust
            let public_key = self
                .generate_btc_public_key(
                    &self
                        .internal_unwrap_btc_pending_info(&btc_pending_sign_id)
                        .vutxos[sign_index]
                        .get_path(),
                )
                .inner;
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L171-195)
```rust
            if btc_pending_info.is_all_signed() {
                let tx_bytes_with_sign = psbt.extract_tx_bytes_with_sign();

                // For ZCash chains, use base64 encoding to save space (1.33x vs 2x overhead for hex)
                // ZCash transactions with Orchard bundles are larger and benefit from compact encoding
                // For Bitcoin chains, keep hex encoding for backward compatibility

                #[cfg(feature = "zcash")]
                let tx_bytes_base64 = {
                    use near_sdk::base64::{engine::general_purpose::STANDARD, Engine};
                    STANDARD.encode(&tx_bytes_with_sign)
                };

                Event::SignedBtcTransaction {
                    account_id: &account_id,
                    tx_id: btc_pending_sign_id.clone(),
                    #[cfg(not(feature = "zcash"))]
                    tx_bytes: &tx_bytes_with_sign,
                    #[cfg(feature = "zcash")]
                    tx_bytes_base64,
                }
                .emit();

                btc_pending_info.tx_bytes_with_sign = Some(tx_bytes_with_sign);
                btc_pending_info.to_pending_verify_stage();
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

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L79-134)
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

        let need_signature_num = psbt.get_input_num();
        let psbt_hex = psbt.serialize();
        let btc_pending_id = psbt.get_pending_id();
        let btc_pending_info = BTCPendingInfo {
            account_id: sender_id.clone(),
            btc_pending_id: btc_pending_id.clone(),
            transfer_amount: amount,
            actual_received_amount,
            withdraw_fee,
            gas_fee,
            burn_amount: actual_received_amount + gas_fee,
            psbt_hex,
            vutxos,
            signatures: vec![None; need_signature_num],
            tx_bytes_with_sign: None,
            create_time_sec: nano_to_sec(env::block_timestamp()),
            last_sign_time_sec: 0,
            state: PendingInfoState::WithdrawOriginal(OriginalState {
                stage: PendingInfoStage::PendingSign,
                max_gas_fee: gas_fee,
                last_rbf_time_sec: None,
                cancel_rbf_reserved: None,
            }),
        };
        require!(
            self.data_mut()
                .btc_pending_infos
                .insert(btc_pending_id.clone(), btc_pending_info.into())
                .is_none(),
            "pending info already exist"
        );
        self.internal_unwrap_mut_account(&sender_id)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());
        Event::UtxoRemoved { utxo_storage_keys }.emit();
```
