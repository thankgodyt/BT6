### Title
MPC Failure Permanently Locks User nBTC in `PendingSign` Withdrawal State — (File: `contracts/satoshi-bridge/src/chain_signature.rs`)

---

### Summary

When a user initiates a withdrawal, the bridge creates a `BTCPendingInfo` in `PendingSign` stage and retains the user's nBTC. It then makes an async cross-contract call to the MPC (chain-signatures) service. If the MPC service permanently stops responding, the `sign_btc_transaction_callback` silently returns `false`, leaving the `BTCPendingInfo` stuck in `PendingSign` forever. No admin or user-facing function exists to cancel a `PendingSign` withdrawal or return the locked nBTC, creating a permanent stuck state with no recovery path — an exact structural analog to M-02.

---

### Finding Description

**Step 1 — Withdrawal initiation locks nBTC and creates pending state.**

When a user calls `ft_transfer_call` on the nBTC token contract, `ft_on_transfer` is invoked on the bridge. For a `Withdraw` message, `create_btc_pending_info` is called, which:
- Moves UTXOs from `utxos` to `unavailable_utxos` (locked)
- Creates a `BTCPendingInfo` with `state: PendingInfoState::WithdrawOriginal(OriginalState { stage: PendingInfoStage::PendingSign, ... })`
- Inserts the pending ID into `account.btc_pending_sign_ids`
- Returns `PromiseOrValue::Promise(...)`, keeping the user's nBTC in the bridge [1](#0-0) 

**Step 2 — Signing is delegated entirely to the MPC service.**

`internal_sign_btc_transaction` dispatches a cross-contract call to `ext_chain_signatures::sign(...)` and chains `sign_btc_transaction_callback` as the only continuation. There is no timeout, no fallback, and no alternative path to advance the state. [2](#0-1) 

**Step 3 — Callback failure leaves state permanently stuck.**

`sign_btc_transaction_callback` is `#[private]` (only callable by the contract itself as a NEAR callback). On MPC failure, `env::promise_result_checked` returns `Err`, the callback returns `false`, and `signatures[sign_index]` remains `None`. The `BTCPendingInfo` stays in `PendingSign` indefinitely. [3](#0-2) 

**Step 4 — No recovery path exists for `PendingSign` withdrawals.**

The only cancellation function is `cancel_withdraw`, which internally requires the transaction to be in `PendingVerify` stage (the parameter is named `original_btc_pending_verify_id`). A `PendingSign` transaction cannot reach `PendingVerify` without a successful MPC callback. [4](#0-3) 

`assert_withdraw_original_pending_verify_tx` enforces this stage gate: [5](#0-4) 

Similarly, `clear_invalid_pending_verify_rbf` only operates on `PendingVerify` RBF transactions and cannot clear a `PendingSign` original withdrawal: [6](#0-5) 

There is no admin function to force-remove a `PendingSign` `BTCPendingInfo`, unlock its UTXOs, or return nBTC to the user. `claim_lost_found` only works if an entry exists in `lost_found`, which is never populated for a stuck `PendingSign` withdrawal. [7](#0-6) 

**Step 5 — Secondary impact: pending sign capacity exhausted.**

Because the stuck `BTCPendingInfo` remains in `account.btc_pending_sign_ids`, it counts against the user's `max_pending_sign_txs` limit. Once the limit is reached, the user cannot initiate any further withdrawals. [8](#0-7) 

---

### Impact Explanation

If the MPC (chain-signatures) service permanently stops responding after a withdrawal has been initiated:

1. The user's nBTC is permanently locked inside the bridge contract with no return path.
2. The reserved UTXOs are permanently locked in `unavailable_utxos`, reducing the bridge's operational UTXO pool.
3. The user's pending sign slot is permanently consumed, blocking future withdrawals.
4. No operator, DAO, or user action can recover the funds without a contract upgrade.

This matches the allowed impact: **Medium — stuck bridge state requiring operator intervention** (and potentially **Critical — permanent locking of user funds**).

---

### Likelihood Explanation

The MPC (chain-signatures) is an external NEAR protocol-level service. Like `randProvider` in M-02, it can be deprecated, experience an outage, or have its contract account deleted. Any withdrawal initiated during such a window enters a permanently unrecoverable state. The trigger is an external dependency failure, but the root cause is the absence of a recovery path in the bridge contract itself — identical to the M-02 root cause pattern.

---

### Recommendation

Add an admin function (restricted to `Role::DAO` or `Role::Operator`) that can cancel a `PendingSign` withdrawal, analogous to the M-02 fix applied to `upgradeRandProvider`:

```rust
#[payable]
#[access_control_any(roles(Role::DAO, Role::Operator))]
pub fn cancel_pending_sign_withdrawal(&mut self, btc_pending_sign_id: String) {
    assert_one_yocto();
    let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id).clone();
    btc_pending_info.assert_pending_sign();
    // Only allow cancellation of original withdrawals (not refunds/management)
    match &btc_pending_info.state {
        PendingInfoState::WithdrawOriginal(_) => {}
        _ => env::panic_str("Only original withdraw PendingSign can be cancelled here"),
    }
    // Restore UTXOs from unavailable back to available
    // Return nBTC (transfer_amount) to user or place in lost_found
    // Remove BTCPendingInfo and clean up account state
}
```

This mirrors the M-02 fix: instead of reverting when the external dependency is broken, provide an escape hatch that resets the stuck state and restores user funds.

---

### Proof of Concept

1. User calls `ft_transfer_call(bridge, 1_000_000, withdraw_msg)` on the nBTC contract.
2. Bridge's `ft_on_transfer` → `create_btc_pending_info` creates `BTCPendingInfo` in `PendingSign`. nBTC is held by bridge.
3. Relayer calls `sign_btc_transaction(btc_pending_sign_id, 0, key_version)`.
4. MPC service is permanently down. `sign_btc_transaction_callback` is called with a failed promise result, returns `false`. `signatures[0]` remains `None`.
5. `cancel_withdraw(btc_pending_sign_id, ...)` → panics: `"Not pending verify stage"`.
6. `clear_invalid_pending_verify_rbf(btc_pending_sign_id)` → panics: `"Not rbf transaction"`.
7. `claim_lost_found()` → panics: `"The account does not have lostfound"`.
8. User's nBTC is permanently locked. UTXOs permanently in `unavailable_utxos`. No recovery path exists without a contract upgrade.

### Citations

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L80-85)
```rust
        let max_pending = self.get_max_pending_sign_txs(&sender_id);
        let account = self.internal_unwrap_or_create_mut_account(&sender_id);
        require!(
            account.pending_sign_count() < max_pending,
            "Too many pending sign transactions"
        );
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L103-133)
```rust
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L449-460)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn claim_lost_found(&mut self) -> Promise {
        assert_one_yocto();
        let account_id = env::predecessor_account_id();
        let amount = self
            .data_mut()
            .lost_found
            .remove(&account_id)
            .expect("The account does not have lostfound");
        self.internal_transfer_nbtc(&account_id, amount)
    }
```

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L194-199)
```rust
    pub fn assert_withdraw_original_pending_verify_tx(&self) {
        match self.state.borrow() {
            PendingInfoState::WithdrawOriginal(state) => state.assert_pending_verify(),
            _ => env::panic_str("Not withdraw original tx"),
        }
    }
```

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L403-413)
```rust
    pub fn internal_clear_invalid_pending_verify_rbf(&mut self, btc_pending_id: String) {
        let btc_pending_info = self.internal_remove_btc_pending_info(&btc_pending_id);
        btc_pending_info.assert_pending_verify();
        let original_tx_id = btc_pending_info
            .get_original_tx_id()
            .expect("Not rbf transaction");
        require!(
            !self.data().rbf_txs.contains_key(original_tx_id),
            "Not invalid pending verify rbf"
        );
    }
```
