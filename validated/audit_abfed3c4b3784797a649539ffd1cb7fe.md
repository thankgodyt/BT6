### Title
No Cancellation Path for Stuck Refund Pending Transactions — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

Once `execute_refund` creates a `BTCPendingInfo` entry in `Refund(PendingSign)` state, there is no mechanism — for any caller, privileged or not — to cancel or remove that pending transaction while the refund request remains active in `refund_requests`. If the MPC signing step fails or stalls, the refund is permanently stuck and `execute_refund` cannot be re-invoked, requiring DAO/Operator intervention to unblock the user's funds.

---

### Finding Description

`finalize_refund_with_psbt` creates a `BTCPendingInfo` in `Refund(OriginalState { stage: PendingSign, … })` state and inserts it into `btc_pending_infos`: [1](#0-0) 

The only public removal path for a refund pending tx is `internal_remove_refund_pending_tx_id`, which hard-blocks removal while the refund request is still present: [2](#0-1) 

The refund request is intentionally kept alive (with `executed = true`) after `execute_refund` runs, and is only removed when `verify_refund_finalize_callback` succeeds: [3](#0-2) [4](#0-3) 

So while the refund request is active, the stuck pending tx cannot be removed.

`execute_refund` also cannot be re-invoked to create a fresh pending tx, because `finalize_refund_with_psbt` requires the `btc_pending_id` (derived deterministically from the PSBT hash of fixed refund inputs) to be absent: [5](#0-4) 

The `do_cancel` method in `BTCPendingInfo` only handles `WithdrawOriginal` and `ActiveUtxoManagementOriginal` states and explicitly panics for any other variant, including `Refund`: [6](#0-5) 

There is no equivalent of `cancel_withdraw` for the refund path. The `cancel_withdraw` function in `bridge.rs` is restricted to `Role::DAO` / `Role::Operator` and routes to `cancel_withdraw_chain_specific`, which only handles withdraw states: [7](#0-6) 

If `sign_btc_transaction_callback` returns `false` (MPC failure), the pending info remains in `PendingSign` state with `signatures[sign_index] = None` and the caller's `btc_pending_sign_ids` slot is still occupied: [8](#0-7) 

The only escape is for DAO/Operator to call `reject_refund` (removing the refund request), after which `remove_refund_pending_tx_id` can clean up the stale pending info.

---

### Impact

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L344-372)
```rust
        let btc_pending_info = BTCPendingInfo {
            account_id: caller.clone(),
            btc_pending_id: btc_pending_id.clone(),
            transfer_amount: 0,
            actual_received_amount: refund_amount,
            withdraw_fee: 0,
            gas_fee,
            burn_amount: 0,
            psbt_hex,
            vutxos: vec![vutxo],
            signatures: vec![None; 1],
            tx_bytes_with_sign: None,
            create_time_sec: nano_to_sec(env::block_timestamp()),
            last_sign_time_sec: 0,
            state: PendingInfoState::Refund(OriginalState {
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
```

**File:** contracts/satoshi-bridge/src/refund.rs (L395-401)
```rust
        // Keep the request (so `execute_refund` can be called again to re-create
        // the transaction) but mark it executed; it is removed only when the
        // refund is finalized in `verify_refund_finalize`.
        refund_request.executed = true;
        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());
```

**File:** contracts/satoshi-bridge/src/refund.rs (L418-424)
```rust
        require!(
            !self
                .data()
                .refund_requests
                .contains_key(&utxo_storage_keys[0]),
            "refund request still active"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L483-485)
```rust
        self.data_mut()
            .refund_requests
            .remove(&utxo_storage_keys[0]);
```

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L271-285)
```rust
    pub fn do_cancel(&mut self, gas_fee: u128, cancel_rbf_reserved: u128) {
        match self.state.borrow_mut() {
            PendingInfoState::WithdrawOriginal(state) => {
                state.max_gas_fee = gas_fee;
                state.last_rbf_time_sec = Some(nano_to_sec(env::block_timestamp()));
                state.cancel_rbf_reserved = Some(cancel_rbf_reserved.into());
            }
            PendingInfoState::ActiveUtxoManagementOriginal(state) => {
                state.max_gas_fee = gas_fee;
                state.last_rbf_time_sec = Some(nano_to_sec(env::block_timestamp()));
                state.cancel_rbf_reserved = Some(cancel_rbf_reserved.into());
            }
            _ => env::panic_str("Not original tx"),
        }
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L283-299)
```rust
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

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L141-213)
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
