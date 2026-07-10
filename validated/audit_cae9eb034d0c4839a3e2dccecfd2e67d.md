Now I have all the information needed for a complete analysis. Let me trace the full path.

### Title
Unprivileged `key_version` Injection in `sign_btc_transaction` Permanently Locks User ZEC — (`contracts/satoshi-bridge/src/api/chain_signatures.rs`)

---

### Summary

`sign_btc_transaction` is a public, permissionless NEAR function that accepts a caller-controlled `key_version` parameter. There is no access-control guard (no trusted-relayer check, no ownership check), and `key_version` is forwarded verbatim to the MPC signing request without validation. An attacker can call this function for any unsigned input of a victim's multi-input Zcash withdrawal before the relayer does, supplying a wrong `key_version`. The MPC will sign with a different key than the one that controls the UTXO, the callback stores the invalid signature, and the assembled transaction fails Zcash script validation. The user's ZEC is permanently locked in the bridge's UTXO set.

---

### Finding Description

**Entry point — no access control:**

`sign_btc_transaction` carries only `#[payable]` and `#[pause(except(roles(Role::DAO)))]`. When the contract is unpaused (normal operation), any NEAR account can call it. There is no `env::predecessor_account_id()` check, no trusted-relayer assertion, and no ownership check against `btc_pending_info.account_id`. [1](#0-0) 

**`key_version` forwarded without validation:**

Inside `internal_sign_btc_transaction`, the caller-supplied `key_version` is placed directly into the `SignRequest` sent to the MPC. No stored expected value is consulted; no range check is performed. [2](#0-1) 

**TOCTOU window — two concurrent calls both pass the guard:**

The only guard against double-signing is `signatures[sign_index].is_none()`, checked synchronously before the async MPC call. Because the MPC call is a cross-contract promise, the state is not updated until the callback fires. A second call for the same `sign_index` (by the relayer or another attacker) will also pass this check if it is processed before either callback returns. [3](#0-2) 

**Callback stores whatever the MPC returns — no key-version re-check:**

`sign_btc_transaction_callback` derives the public key from the VUTXO path using the stored root public key (independent of `key_version`), then stores the MPC-returned signature unconditionally. The `key_version` used during signing is not recorded and not re-validated. [4](#0-3) 

**`generate_btc_public_key` ignores `key_version`:**

The public key embedded in the script signature is always derived from the stored root public key and the VUTXO path — never from `key_version`. If the MPC signed with a different key (selected by a wrong `key_version`), the resulting signature will not verify against the embedded public key. [5](#0-4) 

**Transaction assembly proceeds regardless of signature validity:**

Once `is_all_signed()` returns `true`, `extract_tx_bytes_with_sign()` assembles and serializes the transaction. No cryptographic validity check is performed on the stored signatures before assembly. [6](#0-5) [7](#0-6) 

---

### Impact Explanation

A Zcash withdrawal with N inputs requires N valid signatures, all produced by the key corresponding to each UTXO's locking script. If any input is signed with a wrong `key_version`, the script-sig for that input contains a signature from a different private key. The assembled transaction fails Zcash transparent script validation and cannot be broadcast. The UTXOs have already been removed from the bridge's UTXO set when the withdrawal was initiated, so they cannot be re-used. The user's ZEC is permanently locked.

---

### Likelihood Explanation

The attack requires no privilege. The `btc_pending_sign_id` is publicly observable on-chain (emitted via events and readable from contract state). The attacker only needs to call `sign_btc_transaction` for any unsigned input before the relayer, with a `key_version` value that causes the MPC to sign with a different key. Exploitability depends on whether the production NEAR chain signatures MPC contract accepts `key_version` values beyond `0` (e.g., after a key rotation). If only `key_version=0` is currently valid and the MPC rejects others, the callback receives an error and returns `false` without storing a signature — preventing the attack in that specific scenario. However, the design flaw (no access control, no `key_version` validation) means any future key rotation immediately opens this attack surface. Even today, the absence of access control is a concrete, reachable invariant violation.

---

### Recommendation

1. **Add caller access control**: Restrict `sign_btc_transaction` to trusted relayers or to `btc_pending_info.account_id` (the withdrawal owner), consistent with how `verify_withdraw` and similar functions are gated in `api/bridge.rs`.

2. **Validate `key_version`**: Store the expected `key_version` in `BTCPendingInfo` at withdrawal creation time and assert equality in `internal_sign_btc_transaction`.

3. **Close the TOCTOU window**: Mark the input as "signing in progress" (e.g., a `Signing` variant in the `Option`) atomically before the MPC call, so a second concurrent call for the same index is rejected immediately.

---

### Proof of Concept

```
1. Alice initiates a 2-input Zcash withdrawal.
   → BTCPendingInfo created with signatures = [None, None].
   → btc_pending_sign_id is publicly visible on-chain.

2. Attacker observes the pending ID and calls:
     sign_btc_transaction(btc_pending_sign_id, sign_index=0, key_version=1)
   before the relayer.
   → signatures[0].is_none() == true → passes guard.
   → MPC signs input 0 with key_version=1 (a different key than the UTXO's locking script).

3. Relayer calls sign_btc_transaction(id, 0, key_version=0).
   → signatures[0].is_none() == true (callback not yet returned) → passes guard.
   → MPC signs input 0 with key_version=0 (correct key).

4. Attacker's callback fires first (processed in block order):
   → signatures[0] = Some(invalid_sig_from_wrong_key).

5. Relayer's callback fires:
   → require!(signatures[0].is_none()) → panics with "Already signed".
   → Correct signature is discarded.

6. Relayer calls sign_btc_transaction(id, 1, key_version=0) → correct signature stored.
   → is_all_signed() == true → extract_tx_bytes_with_sign() assembles transaction.

7. Assembled transaction has:
   - input 0: script_sig = sign(wrong_key) + pubkey(correct_key) → INVALID
   - input 1: script_sig = sign(correct_key) + pubkey(correct_key) → valid

8. Transaction broadcast fails Zcash script validation.
   Alice's ZEC is permanently locked in the bridge's UTXO set.
``` [8](#0-7) [9](#0-8) [10](#0-9)

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

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L134-172)
```rust
    #[private]
    pub fn sign_btc_transaction_callback(
        &mut self,
        account_id: AccountId,
        btc_pending_sign_id: String,
        sign_index: usize,
    ) -> bool {
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
            if btc_pending_info.is_all_signed() {
                let tx_bytes_with_sign = psbt.extract_tx_bytes_with_sign();
```

**File:** contracts/satoshi-bridge/src/kdf.rs (L42-51)
```rust
    pub fn generate_btc_public_key(&self, path: &str) -> BtcPublicKey {
        let public_key_bytes = self.generate_public_key(path);
        let uncompressed_btc_public_key =
            BtcPublicKey::from_slice(&public_key_bytes).expect("Invalid public key bytes");
        uncompressed_btc_public_key
            .inner
            .to_string()
            .parse()
            .unwrap()
    }
```

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L299-301)
```rust
    pub fn is_all_signed(&self) -> bool {
        self.signatures.iter().all(Option::is_some)
    }
```
