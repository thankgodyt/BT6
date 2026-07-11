### Title
Arithmetic Underflow in `verify_active_utxo_management_burn_callback` During RBF Finalization — (`contracts/satoshi-bridge/src/nbtc/burn.rs`)

---

### Summary

In the RBF (Replace-By-Fee) path of `verify_active_utxo_management_burn_callback`, the code performs a plain subtraction `reserved_protocol_fee - btc_pending_info.burn_amount` without verifying that the subtrahend does not exceed the minuend. Because the RBF transaction's gas fee (`burn_amount`) can legitimately exceed the original transaction's reserved gas fee (`reserved_protocol_fee`), this subtraction panics, permanently blocking active UTXO management finalization and leaving the bridge's UTXO set in a stuck, inconsistent state.

---

### Finding Description

In `verify_active_utxo_management_burn_callback`, when the pending info belongs to an RBF transaction (`get_original_tx_id()` returns `Some`), the code computes the unused reserved fee as:

```rust
let reserved_protocol_fee = original_tx_btc_pending_info.get_max_gas_fee();
let unused_reserved_protocol_fee =
    reserved_protocol_fee - btc_pending_info.burn_amount;   // ← plain subtraction
self.data_mut().cur_reserved_protocol_fee -= reserved_protocol_fee;
self.data_mut().cur_available_protocol_fee += unused_reserved_protocol_fee;
self.data_mut().acc_protocol_fee_for_gas += btc_pending_info.burn_amount;
``` [1](#0-0) 

Here:
- `reserved_protocol_fee` = `original_tx_btc_pending_info.get_max_gas_fee()`, which is the gas fee of the **original** active UTXO management transaction, set at creation time in `create_active_utxo_management_pending_info` as `max_gas_fee: gas_fee`.
- `btc_pending_info.burn_amount` = the gas fee of the **RBF** transaction, which is set to the new (higher) gas fee when the RBF is initiated. [2](#0-1) 

The entire purpose of RBF is to increase the gas fee. Therefore, `btc_pending_info.burn_amount` (RBF gas fee) will routinely exceed `reserved_protocol_fee` (original gas fee). Both values are bounded by `[min_btc_gas_fee, max_btc_gas_fee]` per `check_psbt_output_all_change_address`, but the original gas fee can be as low as `min_btc_gas_fee` while the RBF gas fee can be as high as `max_btc_gas_fee`. [3](#0-2) 

NEAR contracts are compiled with `overflow-checks = true`, so this plain `u128` subtraction panics when `burn_amount > reserved_protocol_fee`, causing the entire callback to revert.

The same structural issue exists in the non-RBF else-branch at line 211, though in that case `reserved_protocol_fee == burn_amount` at creation time, so it evaluates to zero without underflowing under normal conditions. [4](#0-3) 

---

### Impact Explanation

When the callback panics:

1. The nBTC burn (protocol fee) from the preceding cross-contract call is **already committed** and cannot be rolled back — protocol nBTC is destroyed.
2. The new UTXOs from the RBF transaction are **never added** to `self.data_mut().utxos`.
3. The old UTXOs were **already removed** from the active set in `create_active_utxo_management_pending_info`.
4. `cur_reserved_protocol_fee` is **never decremented**, leaving the protocol fee accounting permanently inflated.

The bridge's UTXO set is now smaller than the actual BTC it controls on-chain. Future withdrawals may fail due to insufficient tracked UTXOs. Recovery requires privileged operator intervention to re-register the missing UTXOs via `verify_migrate_deposit`. This matches **Medium — stuck bridge state requiring operator intervention**.

---

### Likelihood Explanation

Active UTXO management RBF is a normal operational flow: when a consolidation or split transaction is not confirmed in time, a relayer initiates an RBF with a higher fee. The higher fee is the defining characteristic of RBF. Any RBF where the new gas fee exceeds the original gas fee (the common case) triggers the underflow. The `check_psbt_output_all_change_address` validation enforces `gas_fee <= max_btc_gas_fee` but places no upper bound relative to the original gas fee, so the condition is reachable in routine operation.

---

### Recommendation

Replace the plain subtraction with a saturating or checked variant, mirroring the fix pattern from the external report:

```rust
let unused_reserved_protocol_fee = reserved_protocol_fee
    .saturating_sub(btc_pending_info.burn_amount);
```

Or, more precisely, cap `burn_amount` against `reserved_protocol_fee` before computing the unused portion, and separately account for any excess gas fee drawn from `cur_available_protocol_fee` (as is already done in `internal_cancel_withdraw` for the cancel-withdraw RBF path). [5](#0-4) 

---

### Proof of Concept

1. Relayer calls `create_active_utxo_management_pending_info` with a PSBT whose gas fee is `min_btc_gas_fee` (e.g., 1 000 sat). The contract sets `max_gas_fee = 1_000`, reserves 1 000 sat of protocol fee, and removes the input UTXOs from the active set.
2. The transaction is not confirmed. Relayer initiates an active UTXO management RBF with a new PSBT whose gas fee is `max_btc_gas_fee` (e.g., 50 000 sat). The new `BTCPendingInfo` has `burn_amount = 50_000`.
3. The RBF transaction confirms on-chain. A relayer calls `verify_active_utxo_management` → `verify_active_utxo_management_callback` → `verify_active_utxo_management_burn_promise` → the nBTC burn succeeds.
4. `verify_active_utxo_management_burn_callback` is invoked. It enters the `if let Some(original_tx_id)` branch and computes:
   ```
   reserved_protocol_fee = 1_000
   unused_reserved_protocol_fee = 1_000 - 50_000  // panics: underflow
   ```
5. The callback panics. The burn is already committed. The new UTXOs are never registered. The bridge's UTXO set is permanently short the consolidated outputs. [6](#0-5) [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L192-216)
```rust
            if let Some(original_tx_id) = btc_pending_info.get_original_tx_id() {
                self.data_mut().rbf_txs.remove(original_tx_id);
                self.internal_unwrap_mut_account(&btc_pending_info.account_id)
                    .btc_pending_verify_list
                    .remove(original_tx_id);
                let original_tx_btc_pending_info =
                    self.internal_remove_btc_pending_info(original_tx_id);
                let reserved_protocol_fee = original_tx_btc_pending_info.get_max_gas_fee();
                let unused_reserved_protocol_fee =
                    reserved_protocol_fee - btc_pending_info.burn_amount;
                self.data_mut().cur_reserved_protocol_fee -= reserved_protocol_fee;
                self.data_mut().cur_available_protocol_fee += unused_reserved_protocol_fee;
                self.data_mut().acc_protocol_fee_for_gas += btc_pending_info.burn_amount;
            } else {
                self.internal_unwrap_mut_account(&btc_pending_info.account_id)
                    .btc_pending_verify_list
                    .remove(&tx_id);
                let reserved_protocol_fee = btc_pending_info.get_max_gas_fee();
                let unused_reserved_protocol_fee =
                    reserved_protocol_fee - btc_pending_info.burn_amount;
                self.data_mut().cur_reserved_protocol_fee -= reserved_protocol_fee;
                self.data_mut().cur_available_protocol_fee += unused_reserved_protocol_fee;
                self.data_mut().acc_protocol_fee_for_gas += btc_pending_info.burn_amount;
                self.data_mut().rbf_txs.remove(&tx_id);
            }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/active_utxo_management.rs (L67-124)
```rust
    pub fn create_active_utxo_management_pending_info(
        &mut self,
        account_id: AccountId,
        mut psbt: PsbtWrapper,
    ) {
        self.require_pending_sign_capacity(&account_id);

        let (utxo_storage_keys, vutxos) = self.generate_vutxos(&mut psbt);
        let (actual_received_amount, gas_fee) =
            self.check_active_management_psbt_valid(&psbt, &vutxos);
        require!(
            gas_fee <= self.data().cur_available_protocol_fee,
            "Insufficient protocol_fee"
        );
        self.data_mut().cur_available_protocol_fee -= gas_fee;
        self.data_mut().cur_reserved_protocol_fee += gas_fee;

        let need_signature_num = psbt.get_input_num();
        let psbt_hex = psbt.serialize();
        let btc_pending_id = psbt.get_pending_id();
        let btc_pending_info = BTCPendingInfo {
            account_id: account_id.clone(),
            btc_pending_id: btc_pending_id.clone(),
            transfer_amount: 0,
            actual_received_amount,
            withdraw_fee: 0,
            gas_fee,
            burn_amount: gas_fee,
            psbt_hex,
            vutxos,
            signatures: vec![None; need_signature_num],
            tx_bytes_with_sign: None,
            create_time_sec: nano_to_sec(env::block_timestamp()),
            last_sign_time_sec: 0,
            state: PendingInfoState::ActiveUtxoManagementOriginal(OriginalState {
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
        self.internal_unwrap_mut_account(&account_id)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());
        Event::UtxoRemoved { utxo_storage_keys }.emit();
        Event::GenerateBtcPendingInfo {
            account_id: &account_id,
            btc_pending_id: &btc_pending_id,
        }
        .emit();
    }
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L151-160)
```rust
        let gas_fee = input_amount - output_amount;
        if !is_cancel {
            require!(
                gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
                format!(
                    "Invalid gas fee ({}). valid range: [{}, {}].",
                    gas_fee, config.min_btc_gas_fee, config.max_btc_gas_fee
                )
            );
        }
```

**File:** contracts/satoshi-bridge/src/rbf/cancel_withdraw.rs (L55-68)
```rust
        let excess_gas_fee = gas_fee
            .saturating_sub(btc_pending_info.transfer_amount - btc_pending_info.withdraw_fee);
        if excess_gas_fee > 0 {
            require!(
                self.acl_has_role(Role::DAO.into(), predecessor_account_id),
                "gas fee exceeds the user's balance, only the owner is allowed to cancel"
            );
            require!(
                self.data().cur_available_protocol_fee >= excess_gas_fee,
                "Insufficient protocol fee"
            );
            self.data_mut().cur_available_protocol_fee -= excess_gas_fee;
            self.data_mut().cur_reserved_protocol_fee += excess_gas_fee;
        }
```
