Looking at the `execute_refund` re-execution path in `refund.rs` and `finalize_refund_with_psbt`, I can identify a valid analog.

---

### Title
Re-execution of `execute_refund` After Signing Creates Orphaned `BTCPendingInfo` Without Removing the Previous Entry — (`contracts/satoshi-bridge/src/refund.rs`)

### Summary

When `execute_refund` is called on a refund request that already has `executed == true`, the code intentionally permits re-creation of the refund transaction (e.g., after a consensus branch change). However, `finalize_refund_with_psbt` does not remove or invalidate the previous `BTCPendingInfo` before inserting a new one. Once the first pending info has been signed and migrated from `btc_pending_sign_ids` to `btc_pending_verify_list`, the capacity guard passes and a second `BTCPendingInfo` is created for the same deposit UTXO — directly analogous to the delegation bug where the old delegatee entry is never removed before adding the new one.

### Finding Description

`finalize_refund_with_psbt` is the shared finalizer for all `execute_refund` calls. It:

1. Checks `require_pending_sign_capacity` — passes once the first pending info has been signed and moved out of `btc_pending_sign_ids`.
2. Inserts a new `BTCPendingInfo` keyed by the new PSBT's `btc_pending_id` (fails only if the exact same PSBT hash is produced).
3. Adds the new ID to `btc_pending_sign_ids`.
4. Re-marks the UTXO in `verified_deposit_utxo` (no-op, already present).
5. Re-sets `refund_request.executed = true` (no-op).

Critically, **step 2 never removes the previous `BTCPendingInfo`** that is now sitting in `btc_pending_verify_list`. The old entry is not invalidated, not cleaned up, and not referenced by the new one. [1](#0-0) 

The capacity guard only inspects `btc_pending_sign_ids.len()`: [2](#0-1) 

Once the first `BTCPendingInfo` is signed and transitions to `PendingVerify` (removed from `btc_pending_sign_ids`, added to `btc_pending_verify_list`), `pending_sign_count()` drops to zero and the guard passes unconditionally, allowing a second `BTCPendingInfo` to be created for the same deposit UTXO. [3](#0-2) 

### Impact Explanation

Two MPC-signed refund transactions now exist for the same Bitcoin UTXO. Only one can confirm on-chain (Bitcoin prevents double-spending). After the first confirms and `verify_refund_finalize_callback` removes the refund request and the first `BTCPendingInfo`, the second `BTCPendingInfo` becomes permanently orphaned:

- It cannot be finalized (the refund request is gone, so `verify_refund_finalize` will find no matching request key).
- It cannot be self-removed by the user (`remove_refund_pending_tx_id` is `#[trusted_relayer]`-gated).
- It occupies on-chain storage indefinitely until a trusted relayer calls `remove_refund_pending_tx_id`. [4](#0-3) [5](#0-4) 

This is a **Medium** impact: stuck bridge state requiring operator intervention, matching the allowed impact class "stuck bridge state requiring operator intervention."

### Likelihood Explanation

`execute_refund` is a public, unpermissioned function callable by any NEAR account after the timelock elapses: [6](#0-5) 

Any user who submitted a refund request can trigger this by calling `execute_refund` a second time after the first PSBT has been signed by MPC. The signing pipeline is automated, so the window between first signing and second `execute_refund` call is reliably reachable.

### Recommendation

Before inserting a new `BTCPendingInfo` in `finalize_refund_with_psbt`, check whether a previous pending info for this refund request already exists (e.g., by storing the previous `btc_pending_id` on the `RefundRequest`). If one exists and is still in `PendingVerify` stage, either reject the re-execution or explicitly remove the old entry first — mirroring the fix applied to the delegation bug (remove the old entry before adding the new one).

### Proof of Concept

1. Alice submits `request_refund` for UTXO `txid@0`. A `RefundRequest` is stored with `executed = false`.
2. After the timelock, Bob calls `execute_refund("txid@0", ...)`. `finalize_refund_with_psbt` creates `BTCPendingInfo_1` (PSBT_1), adds its ID to `btc_pending_sign_ids`, sets `executed = true`.
3. MPC signs PSBT_1. The signing callback moves `BTCPendingInfo_1`'s ID from `btc_pending_sign_ids` to `btc_pending_verify_list`. `pending_sign_count()` is now 0.
4. Bob calls `execute_refund("txid@0", ...)` again. `load_refund_request_for_execute` passes because `executed == true` is the allowed re-entry condition. `require_pending_sign_capacity` passes because `btc_pending_sign_ids` is empty. `finalize_refund_with_psbt` creates `BTCPendingInfo_2` (PSBT_2, different fee → different hash), adds its ID to `btc_pending_sign_ids`. `BTCPendingInfo_1` is never removed.
5. MPC signs PSBT_2. Now two signed refund transactions exist for `txid@0`.
6. PSBT_1 confirms on Bitcoin. `verify_refund_finalize_callback` removes the refund request and `BTCPendingInfo_1`. `BTCPendingInfo_2` remains orphaned in `btc_pending_verify_list` with no refund request to finalize against, requiring a trusted relayer to call `remove_refund_pending_tx_id` to clean up. [7](#0-6) [8](#0-7)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L230-261)
```rust
    /// Load a refund request and run the common pre-execution checks
    /// (timelock elapsed, not already finalized via deposit).
    pub(crate) fn load_refund_request_for_execute(
        &self,
        utxo_storage_key: &str,
        timelock_sec: u64,
    ) -> RefundRequest {
        let refund_request: RefundRequest = self
            .data()
            .refund_requests
            .get(utxo_storage_key)
            .expect("Refund request not found")
            .into();

        let now = nano_to_sec(env::block_timestamp());
        require!(
            u64::from(now) >= u64::from(refund_request.created_at_sec) + timelock_sec,
            "Refund timelock has not passed yet"
        );

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

**File:** contracts/satoshi-bridge/src/refund.rs (L315-401)
```rust
    pub(crate) fn finalize_refund_with_psbt(
        &mut self,
        caller: AccountId,
        mut refund_request: RefundRequest,
        psbt: PsbtWrapper,
        refund_amount: u128,
        utxo_storage_key: String,
    ) {
        let gas_fee = refund_request.gas_fee;
        let refund_address = refund_request.refund_address.clone();

        let deposit_msg = refund_request.deposit_msg();
        let path = get_deposit_path(&deposit_msg);
        let vutxo = VUTXO::Current(UTXO {
            path,
            tx_bytes: refund_request.tx_bytes.0.clone(),
            vout: refund_request.vout,
            balance: u64::try_from(refund_request.amount)
                .unwrap_or_else(|_| env::panic_str("Amount overflow")),
        });

        let psbt_hex = psbt.serialize();
        let btc_pending_id = psbt.get_pending_id();

        if !self.check_account_exists(&caller) {
            self.internal_set_account(&caller, crate::Account::new(&caller));
        }
        self.require_pending_sign_capacity(&caller);

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
        self.internal_unwrap_mut_account(&caller)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());

        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());

        Event::RefundExecuted {
            utxo_storage_key: utxo_storage_key.clone(),
            amount: refund_request.amount.into(),
            refund_address,
        }
        .emit();

        Event::GenerateBtcPendingInfo {
            account_id: &caller,
            btc_pending_id: &btc_pending_id,
        }
        .emit();

        // Keep the request (so `execute_refund` can be called again to re-create
        // the transaction) but mark it executed; it is removed only when the
        // refund is finalized in `verify_refund_finalize`.
        refund_request.executed = true;
        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());
```

**File:** contracts/satoshi-bridge/src/refund.rs (L462-494)
```rust
    pub fn verify_refund_finalize_callback(&mut self, tx_id: String) -> bool {
        let result_bytes = env::promise_result_checked(0, MAX_BOOL_RESULT)
            .expect("Call verify_transaction_inclusion failed");
        let is_valid = serde_json::from_slice::<bool>(&result_bytes)
            .expect("verify_transaction_inclusion return not bool");
        require!(is_valid, "verify_transaction_inclusion return false");

        let btc_pending_info = self.internal_unwrap_btc_pending_info(&tx_id).clone();
        btc_pending_info.assert_refund_pending_verify_tx();

        let account_id = btc_pending_info.account_id.clone();

        // A refund spends exactly one deposit UTXO, whose key is the refund request
        // key. More than one input would be abnormal for a refund.
        let utxo_storage_keys = btc_pending_info.get_psbt().get_utxo_storage_keys();
        require!(
            utxo_storage_keys.len() == 1,
            "refund transaction must spend exactly one input"
        );
        // Refund confirmed on-chain → drop the request so no further execute_refund
        // is possible. If it was already removed, this is harmlessly a no-op.
        self.data_mut()
            .refund_requests
            .remove(&utxo_storage_keys[0]);

        // Clean up: remove pending info
        self.internal_remove_btc_pending_info(&tx_id);
        self.internal_unwrap_mut_account(&account_id)
            .btc_pending_verify_list
            .remove(&tx_id);

        true
    }
```

**File:** contracts/satoshi-bridge/src/account.rs (L99-101)
```rust
    pub fn pending_sign_count(&self) -> u32 {
        u32::try_from(self.btc_pending_sign_ids.len()).unwrap_or(u32::MAX)
    }
```

**File:** contracts/satoshi-bridge/src/account.rs (L113-123)
```rust
    pub fn require_pending_sign_capacity(&self, account_id: &AccountId) {
        require!(
            self.get_account(account_id)
                .unwrap_or_else(|| {
                    env::panic_str(&format!("ERR_ACCOUNT_NOT_REGISTERED: {}", account_id))
                })
                .pending_sign_count()
                < self.get_max_pending_sign_txs(account_id),
            "Too many pending sign transactions"
        );
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L580-589)
```rust
    #[payable]
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L622-626)
```rust
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn remove_refund_pending_tx_id(&mut self, tx_id: String) {
        self.internal_remove_refund_pending_tx_id(tx_id);
    }
```
