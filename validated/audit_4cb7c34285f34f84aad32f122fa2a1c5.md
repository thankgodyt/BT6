### Title
Unrestricted `sign_btc_transaction` Allows Any Caller to Corrupt Pending Withdrawal Signing State — (File: `contracts/satoshi-bridge/src/api/chain_signatures.rs`)

---

### Summary

The public function `sign_btc_transaction` imposes no restriction on who may call it. Any unprivileged NEAR account can invoke it against any victim's pending withdrawal, supplying an arbitrary `key_version`. The MPC network will sign the payload with the key corresponding to that version; the callback unconditionally saves whatever signature is returned and marks the input slot as `Some(...)`. Once marked, the slot cannot be overwritten — subsequent legitimate calls revert with `"Already signed"`. If the attacker supplies a `key_version` that differs from the one used to derive the UTXO's public key, the saved signature is cryptographically invalid for the PSBT, the assembled transaction cannot be broadcast successfully, and the user's burned nBTC is unrecoverable without privileged operator intervention.

---

### Finding Description

`sign_btc_transaction` in `contracts/satoshi-bridge/src/api/chain_signatures.rs` is decorated only with `#[payable]` and `#[pause(...)]`. There is no check that `env::predecessor_account_id()` matches `btc_pending_info.account_id`: [1](#0-0) 

The function delegates to `internal_sign_btc_transaction`, which forwards the caller-supplied `key_version` verbatim to the MPC: [2](#0-1) 

The callback derives the expected public key from the UTXO path (tied to the contract's stored root key, i.e. the canonical `key_version`), then unconditionally stores whatever signature the MPC returned and marks the slot occupied: [3](#0-2) 

The "already signed" guard then permanently blocks any re-signing of that slot: [4](#0-3) 

When all slots are filled (even with invalid signatures) the pending info transitions to `PendingVerify` and the signed transaction bytes are emitted for broadcast: [5](#0-4) 

A withdrawal's `BTCPendingInfo` is created with one signature slot per UTXO input: [6](#0-5) 

The nBTC burn amount is committed at creation time and the tokens are already gone before any signing occurs.

---

### Impact Explanation

An attacker who calls `sign_btc_transaction` for a victim's pending withdrawal with a wrong `key_version` causes the MPC to produce a signature under a different derived key. That signature is saved and the slot is permanently locked. The assembled Bitcoin transaction carries an invalid witness and will be rejected by the Bitcoin network. The victim's nBTC has already been burned; the corresponding BTC remains locked in the bridge's UTXO set. Recovery requires a privileged `cancel_withdraw` call (DAO/Operator only): [7](#0-6) 

Without operator intervention the user suffers a permanent loss of their burned nBTC with no on-chain recourse. This matches **Medium — stuck bridge state requiring operator intervention**, and borders on **Critical — permanent locking of user funds** if the operator does not act.

---

### Likelihood Explanation

The attack is fully permissionless: any NEAR account can call `sign_btc_transaction` with a known `btc_pending_sign_id` (emitted as a public event `GenerateBtcPendingInfo`), a target `sign_index`, and an arbitrary `key_version`. The attacker must attach enough NEAR to cover the MPC signing fee, which is a bounded, non-prohibitive cost. Pending sign IDs are observable on-chain, making victim selection trivial. No privileged access, leaked key, or social engineering is required.

---

### Recommendation

Add a caller check at the top of `sign_btc_transaction` to ensure only the owner of the pending transaction (or a privileged role) may trigger signing:

```rust
require!(
    env::predecessor_account_id() == btc_pending_info.account_id
        || self.acl_has_any_role(vec![Role::DAO.into(), Role::Operator.into()],
                                  env::predecessor_account_id()),
    "sign_btc_transaction: caller is not the transaction owner"
);
```

Additionally, validate `key_version` against the contract's configured canonical key version before forwarding to the MPC, so that even a privileged caller cannot accidentally corrupt a signing slot with a stale key version.

---

### Proof of Concept

1. Alice initiates a withdrawal: calls `ft_transfer_call` on the nBTC contract with a `Withdraw` message. Her nBTC is burned. The bridge creates `BTCPendingInfo` with id `PENDING_ID` and emits `GenerateBtcPendingInfo`.

2. Bob (attacker) observes `PENDING_ID` on-chain.

3. Bob calls:
   ```
   sign_btc_transaction(
       btc_pending_sign_id = PENDING_ID,
       sign_index = 0,
       key_version = 999   // wrong version
   )
   ```
   attaching sufficient NEAR for the MPC fee.

4. The MPC signs the payload under key version 999 (a different derived key). `sign_btc_transaction_callback` saves the returned signature into `signatures[0]` and marks the slot `Some(...)`.

5. Alice attempts `sign_btc_transaction(PENDING_ID, 0, 0)`. The call reverts: `"Already signed"`.

6. If the transaction has only one input, it immediately transitions to `PendingVerify` with the invalid signature. The relayer broadcasts it; Bitcoin nodes reject it. Alice's nBTC is gone and her BTC is locked. She must wait for DAO/Operator to call `cancel_withdraw` to recover.

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

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L153-158)
```rust
            let btc_pending_info = self.internal_unwrap_mut_btc_pending_info(&btc_pending_sign_id);
            require!(
                btc_pending_info.signatures[sign_index].is_none(),
                "Already signed"
            );
            btc_pending_info.signatures[sign_index] = Some(signature.clone());
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

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L100-113)
```rust
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
