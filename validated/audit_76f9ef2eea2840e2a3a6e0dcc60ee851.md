### Title
Unprivileged Caller Can Permanently Lock Bridge UTXOs via Arbitrary `key_version` in `sign_btc_transaction` — (`contracts/satoshi-bridge/src/api/chain_signatures.rs`, `chain_signature.rs`)

---

### Summary

`sign_btc_transaction` is a public, payable function with no ownership check. Any caller can invoke it for any victim's `btc_pending_sign_id` and supply an arbitrary `key_version`. The `key_version` is forwarded verbatim to the MPC `sign` call. If the MPC contract accepts `key_version=1`, the returned signature — produced under a different key than the one embedded in the PSBT — is stored unconditionally. A subsequent re-sign attempt is permanently blocked by the `"Already signed"` guard. The resulting PSBT carries an invalid witness, the Bitcoin transaction fails script validation, and the UTXO is permanently unspendable.

---

### Finding Description

**Step 1 — No caller ownership check.**

`sign_btc_transaction` carries only `#[pause(except(roles(Role::DAO)))]`. There is no `require!(env::predecessor_account_id() == btc_pending_info.account_id, ...)` guard. Any NEAR account can call it for any `btc_pending_sign_id`. [1](#0-0) 

**Step 2 — `key_version` is caller-controlled and forwarded verbatim.**

`internal_sign_btc_transaction` constructs `SignRequest { payload, path, key_version }` directly from the caller-supplied value and passes it to the MPC `sign` call. No validation or clamping to `0` occurs. [2](#0-1) 

**Step 3 — Callback stores the signature without cryptographic verification.**

`sign_btc_transaction_callback` deserializes whatever the MPC returns and stores it at `signatures[sign_index]`. It derives the expected public key via `generate_btc_public_key` (which always uses `chain_signatures_root_public_key`, i.e. `key_version=0`), but it never verifies that the received signature is valid under that key before storing it. [3](#0-2) 

**Step 4 — Re-sign is permanently blocked.**

Both `internal_sign_btc_transaction` (pre-call guard) and `sign_btc_transaction_callback` (post-call guard) enforce:

```rust
require!(btc_pending_info.signatures[sign_index].is_none(), "Already signed");
```

Once a `Some(signature)` is written — even an invalid one — no recovery path exists to clear it. [4](#0-3) [5](#0-4) 

**Step 5 — `save_signature` embeds the invalid witness without script validation.**

`psbt.save_signature(sign_index, signature, public_key)` writes `Witness::p2wpkh(&signature.to_btc_signature(), &public_key)` into the PSBT input. The `public_key` is from `key_version=0`; the signature is from `key_version=1`. The witness is cryptographically invalid. `extract_tx_bytes_with_sign()` serializes this broken transaction, which Bitcoin nodes will reject. [6](#0-5) 

---

### Impact Explanation

If the MPC contract accepts `key_version=1` (the NEAR chain-signatures protocol is explicitly designed to support key rotation via `key_version`), the attack produces a `BTCPendingInfo` whose `signatures[sign_index]` is `Some(invalid_sig)`. The PSBT is serialized with a bad witness, the state transitions to `PendingVerify`, and the signed transaction is broadcast. Bitcoin nodes reject it. The UTXO is permanently unspendable because:

- The `"Already signed"` guard blocks any re-sign attempt.
- No function in the contract clears or resets `signatures`.
- The state has already advanced out of `PendingSign`.

This constitutes **permanent locking of bridge-held BTC** — a Critical/Medium impact under the allowed scope ("attacker-triggered permanent locking of bridged funds" / "chain-signature failure that causes permanent loss").

---

### Likelihood Explanation

**Conditional on MPC accepting `key_version=1`.** The NEAR chain-signatures MPC contract accepts `key_version` as a protocol parameter for key rotation. If the deployed MPC instance only supports `key_version=0`, the `sign` call fails, `promise_result_checked` returns `Err`, the callback returns `false`, and no signature is stored — the attack is a no-op. However:

- The bridge contract performs **zero validation** of `key_version`, so the exploitability window is entirely determined by the MPC contract's current key-version support, which can change at any time.
- The lack of caller ownership check is unconditional and is a standalone bug regardless of `key_version`.

---

### Recommendation

1. **Enforce caller ownership**: At the top of `sign_btc_transaction`, add:
   ```rust
   require!(
       env::predecessor_account_id() == btc_pending_info.account_id,
       "Unauthorized"
   );
   ```
2. **Validate `key_version`**: Reject any value other than the expected version (e.g., `0`) before calling MPC:
   ```rust
   require!(key_version == 0, "Invalid key_version");
   ```
3. **Verify signature in callback**: Before storing, verify the MPC-returned signature against the derived `key_version=0` public key and the known payload hash.

---

### Proof of Concept

```
1. Alice initiates a withdrawal; a BTCPendingInfo with btc_pending_sign_id=X enters PendingSign.
2. Attacker (any NEAR account) calls:
       sign_btc_transaction(X, sign_index=0, key_version=1)
   with attached deposit.
3. Bridge calls MPC.sign({ payload, path, key_version: 1 }).
   [If MPC accepts key_version=1, it returns a signature under a different key.]
4. sign_btc_transaction_callback stores signatures[0] = Some(sig_from_key1).
5. Alice (or relayer) calls sign_btc_transaction(X, 0, key_version=0).
   → panics: "Already signed".
6. is_all_signed() returns true; extract_tx_bytes_with_sign() produces a tx
   with an invalid p2wpkh witness (sig from key1, pubkey from key0).
7. Bitcoin nodes reject the transaction. UTXO is permanently locked.
``` [1](#0-0) [7](#0-6) [8](#0-7)

### Citations

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

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L141-170)
```rust
        if let Ok(result_bytes) = env::promise_result_checked(0, MAX_SIGNATURE_RESULT) {
            let signature = serde_json::from_slice::<SignatureResponse>(&result_bytes)
                .expect("Invalid signature");

            let public_key = self
                .generate_btc_public_key(
                    &self
                        .internal_unwrap_btc_pending_info(&btc_pending_sign_id)
                        .vutxos[sign_index]
                        .get_path(),
                )
                .inner;
            let btc_pending_info = self.internal_unwrap_mut_btc_pending_info(&btc_pending_sign_id);
            require!(
                btc_pending_info.signatures[sign_index].is_none(),
                "Already signed"
            );
            btc_pending_info.signatures[sign_index] = Some(signature.clone());
            btc_pending_info.last_sign_time_sec = nano_to_sec(env::block_timestamp());
            Event::BtcInputSignature {
                account_id: &account_id,
                btc_pending_id: &btc_pending_sign_id,
                sign_index,
                signature: &signature,
            }
            .emit();
            let mut psbt = btc_pending_info.get_psbt();
            psbt.save_signature(sign_index, signature, public_key);

            btc_pending_info.psbt_hex = psbt.serialize();
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
