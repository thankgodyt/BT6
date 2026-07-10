### Title
Excess NEAR Attached to `sign_btc_transaction` Is Forwarded Wholesale to Chain Signatures Without Fee Validation, Causing Permanent Loss - (File: contracts/satoshi-bridge/src/chain_signature.rs)

### Summary
`sign_promise` blindly forwards the caller's entire `env::attached_deposit()` to the external chain-signatures contract's `sign` function. Because the chain-signatures contract only enforces a minimum fee and does not refund any surplus, any NEAR attached above the required signing fee is permanently lost to the caller.

### Finding Description
`sign_btc_transaction` in `api/chain_signatures.rs` is marked `#[payable]`, so callers may attach an arbitrary amount of NEAR. The attached deposit is passed unchanged into `internal_sign_btc_transaction`, which calls `sign_promise`:

```rust
pub fn sign_promise(&self, request: SignRequest) -> Promise {
    let config = self.internal_config();
    ext_chain_signatures::ext(config.chain_signatures_account_id.clone())
        .with_static_gas(GAS_FOR_SIGN_CALL)
        .with_attached_deposit(env::attached_deposit())   // ← entire deposit forwarded
        .sign(request)
}
``` [1](#0-0) 

The chain-signatures `sign` function requires a protocol-defined fee and only checks `attached >= required_fee`; it does not return the surplus. There is no call to `pyth.getUpdateFee`-equivalent before forwarding, and the `sign_btc_transaction_callback` contains no refund path for excess NEAR: [2](#0-1) 

The public entry point that exposes this to any caller: [3](#0-2) 

### Impact Explanation
Any NEAR attached above the exact signing fee is consumed by the chain-signatures contract and never returned to the caller or the bridge. This is a direct, permanent loss of user funds on every `sign_btc_transaction` call where the caller over-attaches. Because the required fee is not surfaced by the bridge contract before the call, and because the fee can change as the NEAR chain-signatures protocol evolves, users have no reliable way to attach the exact amount without risking loss.

**Impact: Medium** — permanent loss of user NEAR funds on a publicly reachable bridge path, without direct theft of nBTC/BTC.

### Likelihood Explanation
**Likelihood: Medium** — the signing fee is not documented or validated on-chain by the bridge, so any caller who attaches a round number or a stale cached fee value will silently lose the surplus. The fee is also subject to change by the chain-signatures protocol, making the correct value a moving target.

### Recommendation
Before forwarding the deposit, query the chain-signatures contract for the exact required fee and validate `env::attached_deposit()` against it, then forward only that amount:

```rust
pub fn sign_promise(&self, request: SignRequest) -> Promise {
    let config = self.internal_config();
    let required_fee = ext_chain_signatures::ext(config.chain_signatures_account_id.clone())
        .get_required_fee();   // query exact fee first
    require!(
        env::attached_deposit() == required_fee,
        "Attached deposit must equal the exact signing fee"
    );
    ext_chain_signatures::ext(config.chain_signatures_account_id.clone())
        .with_static_gas(GAS_FOR_SIGN_CALL)
        .with_attached_deposit(required_fee)
        .sign(request)
}
```

Alternatively, refund any surplus to `env::predecessor_account_id()` after the signing call completes in `sign_btc_transaction_callback`.

### Proof of Concept
1. Caller invokes `sign_btc_transaction(btc_pending_sign_id, sign_index, key_version)` with `attached_deposit = 2 NEAR` while the chain-signatures protocol only requires `1 NEAR`.
2. `internal_sign_btc_transaction` calls `sign_promise`, which executes `ext_chain_signatures::sign` with `attached_deposit = 2 NEAR`.
3. The chain-signatures contract accepts the call (fee satisfied), retains all `2 NEAR`, and returns the signature.
4. `sign_btc_transaction_callback` processes the signature successfully with no refund logic.
5. The caller permanently loses `1 NEAR` of overpayment with no on-chain recourse. [1](#0-0) [3](#0-2)

### Citations

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L62-68)
```rust
    pub fn sign_promise(&self, request: SignRequest) -> Promise {
        let config = self.internal_config();
        ext_chain_signatures::ext(config.chain_signatures_account_id.clone())
            .with_static_gas(GAS_FOR_SIGN_CALL)
            .with_attached_deposit(env::attached_deposit())
            .sign(request)
    }
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L134-213)
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

                let is_original_tx = btc_pending_info.get_original_tx_id().is_none();
                let account = self.internal_unwrap_mut_account(&account_id);
                require!(
                    account.btc_pending_sign_ids.remove(&btc_pending_sign_id),
                    "Internal error"
                );
                if is_original_tx {
                    account
                        .btc_pending_verify_list
                        .insert(btc_pending_sign_id.clone());
                }
            }
            true
        } else {
            false
        }
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
