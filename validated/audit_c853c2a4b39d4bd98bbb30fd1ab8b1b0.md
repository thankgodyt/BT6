### Title
Unprivileged Caller Can Invoke `sign_btc_transaction` with Arbitrary `key_version`, Permanently Corrupting Withdrawal Signature Slots — (File: `contracts/satoshi-bridge/src/api/chain_signatures.rs`)

---

### Summary

`sign_btc_transaction` is a public, state-mutating function that triggers the MPC chain-signature service and writes the resulting signature into a withdrawal's pending-info slot. It carries only a `#[pause]` guard and **no role restriction**, so any unprivileged NEAR account can call it with an attacker-chosen `key_version`. The MPC service will sign the correct payload with the wrong key, producing a signature that is cryptographically invalid for the UTXO's locking script. Because the slot is then marked `Some(…)`, the legitimate relayer is permanently blocked from re-signing, leaving the withdrawal stuck.

---

### Finding Description

`sign_btc_transaction` in `contracts/satoshi-bridge/src/api/chain_signatures.rs` is decorated only with `#[payable]` and `#[pause(except(roles(Role::DAO)))]`: [1](#0-0) 

Compare this with every other sensitive bridge entry-point, which carries `#[trusted_relayer]` or `#[access_control_any(roles(…))]`: [2](#0-1) [3](#0-2) 

Inside `internal_sign_btc_transaction`, the caller-supplied `key_version` is forwarded verbatim to the MPC `sign` call: [4](#0-3) 

The callback then stores whatever signature the MPC service returns and marks the slot occupied: [5](#0-4) 

The guard that prevents re-signing is checked **before** the MPC call: [6](#0-5) 

Once the slot is `Some(…)`, no further call to `sign_btc_transaction` for that index can proceed. The public key saved alongside the signature is derived from the UTXO path (correct), but the signature itself was produced by the MPC key at the wrong `key_version`, so the resulting Bitcoin transaction carries an invalid witness and can never be broadcast.

---

### Impact Explanation

The user's nBTC is held by the bridge from the moment `ft_on_transfer` is called. The BTC UTXOs are moved to `unavailable_utxos`. If all signature slots are poisoned with wrong-`key_version` signatures, the withdrawal transaction is permanently invalid on Bitcoin. The user cannot recover nBTC without DAO/Operator calling `cancel_withdraw`, which requires privileged intervention. At scale, an attacker can grief every in-flight withdrawal simultaneously, causing a stuck bridge state requiring operator intervention for every affected user.

**Impact class**: Medium — attacker-triggered locking of bridged funds / stuck bridge state requiring operator intervention. [7](#0-6) 

---

### Likelihood Explanation

The function is fully public, requires no special role, and costs only the NEAR gas fee plus the MPC signing deposit. An attacker only needs to watch the chain for new `BTCPendingInfo` entries (emitted as `GenerateBtcPendingInfo` events) and race to call `sign_btc_transaction` before the legitimate relayer. Because NEAR transaction ordering is deterministic within a block, a well-timed attacker can reliably win the race. No leaked keys, no privileged access, and no third-party compromise are required. [8](#0-7) 

---

### Recommendation

Add the same `#[trusted_relayer]` (or at minimum `#[access_control_any(roles(Role::DAO, Role::Operator, Role::UnrestrictedRelayer))]`) guard that protects every other sensitive bridge entry-point:

```rust
#[payable]
#[trusted_relayer]          // ← add this
#[pause(except(roles(Role::DAO)))]
pub fn sign_btc_transaction(
    &mut self,
    btc_pending_sign_id: String,
    sign_index: usize,
    key_version: u32,
) -> PromiseOrValue<bool> {
```

Additionally, consider validating that `key_version` matches the value recorded in the contract's configuration or the pending-info, so even a whitelisted relayer cannot supply an unexpected version.

---

### Proof of Concept

1. User calls `ft_transfer_call` on the nBTC contract with a `Withdraw` message. The bridge creates a `BTCPendingInfo` with `signatures: vec![None; N]` and emits `GenerateBtcPendingInfo`.
2. Attacker observes the event and immediately calls:
   ```
   sign_btc_transaction(
       btc_pending_sign_id = "<victim's pending id>",
       sign_index = 0,
       key_version = 9999,   // wrong version
   )
   ```
   with sufficient attached NEAR for the MPC fee.
3. `internal_sign_btc_transaction` passes `key_version = 9999` to the MPC `sign` call. The MPC service returns a valid ECDSA signature, but one produced by the key at version 9999, not the key that controls the UTXO.
4. `sign_btc_transaction_callback` stores the bad signature: `signatures[0] = Some(bad_sig)`.
5. The legitimate relayer calls `sign_btc_transaction(…, sign_index=0, key_version=0)` — it panics with `"Already signed"`.
6. The attacker repeats for all remaining `sign_index` values.
7. Once all slots are filled, the state transitions to `PendingVerify`. The signed transaction is broadcast but rejected by Bitcoin nodes (invalid witness). `verify_withdraw` can never succeed. The user's nBTC remains locked in the bridge indefinitely until a DAO/Operator calls `cancel_withdraw`. [9](#0-8) [10](#0-9)

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L70-73)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn verify_deposit_v2(
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L240-242)
```rust
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn verify_withdraw_v2(&mut self, tx_id: String, proof: TxInclusionProof) -> Promise {
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L282-299)
```rust
    #[payable]
    #[access_control_any(roles(Role::DAO, Role::Operator))]
    #[pause(except(roles(Role::DAO)))]
    pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
        assert_one_yocto();
        let user_account_id = self
            .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
            .account_id
            .clone();
        self.require_pending_sign_capacity(&user_account_id);

        self.cancel_withdraw_chain_specific(
            user_account_id,
            original_btc_pending_verify_id,
            output,
            None,
        );
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

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L134-158)
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
```
