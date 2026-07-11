Now I have all the code needed to trace the full path. Let me verify the key facts:

### Title
Unvalidated Orchard Bundle in Cancel-Active-UTXO-Management RBF Enables ZEC Theft to Attacker Shielded Address — (`contracts/satoshi-bridge/src/rbf/cancel_active_utxo_management.rs` + `zcash_utils/psbt_wrapper.rs`)

---

### Summary

`internal_cancel_active_utxo_management` validates the cancel RBF PSBT exclusively through `check_psbt_output_all_change_address(is_cancel=true)`. That function only iterates over transparent outputs, skips the gas-fee range check, and never calls `check_psbt_chain_specific` — the sole site where Orchard bundle validation occurs. An attacker who submits a cancel PSBT embedding an Orchard bundle paying their own shielded address will have the Orchard amount silently absorbed into the computed `gas_fee`, the PSBT accepted, and the bridge's chain-signature mechanism will sign a transaction that diverts bridge-held ZEC to the attacker.

---

### Finding Description

**Step 1 — Validation path for cancel-active-UTXO-management**

`check_cancel_active_utxo_management_rbf_psbt_valid` delegates entirely to `check_psbt_output_all_change_address` with `is_cancel = true`: [1](#0-0) 

**Step 2 — `check_psbt_output_all_change_address` only sees transparent outputs**

`output_amount` is computed solely from `psbt.get_output()`, which returns only `self.vout` (transparent outputs). The Orchard bundle is never queried here: [2](#0-1) 

`gas_fee = input_amount − transparent_output_amount`. If an Orchard bundle carrying amount X is present, X is silently included in `gas_fee` rather than being accounted for as a separate output.

**Step 3 — Gas-fee range check is skipped for `is_cancel = true`** [3](#0-2) 

No upper bound on `gas_fee` is enforced, so an arbitrarily large Orchard amount passes.

**Step 4 — Orchard bundle validation only exists in `check_psbt_chain_specific`, which is never called here** [4](#0-3) 

`check_psbt_chain_specific` is called only from `check_withdraw_psbt` (line 260 of `psbt.rs`). It is **not** called from `check_psbt_output_all_change_address`, so the cancel-active-UTXO-management path never reaches Orchard validation.

**Step 5 — No account-based access control on the cancel function**

The `_account_id` parameter is unused (underscore prefix). The only precondition is the timelock: [5](#0-4) 

Any caller may invoke this after `max_btc_tx_pending_sec` elapses.

**Step 6 — The inflated `gas_fee` passes the protocol-fee guard and the PSBT is stored for signing** [6](#0-5) 

`additional_gas_amount = gas_fee − max_gas_fee` must be ≤ `cur_available_protocol_fee`. The attacker sets the Orchard amount to satisfy this bound (e.g., just above `max_gas_fee`), the PSBT is stored with `PendingInfoStage::PendingSign`, and the bridge's chain-signature mechanism signs it — committing to the Orchard bundle in the sighash.

**Step 7 — `get_hash_to_sign` commits to the Orchard bundle** [7](#0-6) 

The signed transaction is a valid Zcash v5 transaction that pays the attacker's shielded address.

---

### Impact Explanation

Bridge-held ZEC is diverted to an attacker-controlled Orchard shielded address. The bridge's accounting records the stolen amount as gas fees. The maximum theft per exploit is bounded by `max_gas_fee + cur_available_protocol_fee − actual_network_fee`, which can be substantial depending on the protocol fee reserve. This is unauthorized redirection of bridge-controlled funds — Critical impact.

---

### Likelihood Explanation

The only precondition is waiting for `max_btc_tx_pending_sec` to elapse on any active UTXO management transaction, which is a normal operational event. No privileged role, leaked key, or external dependency is required. The exploit is fully constructable off-chain and submitted through the public cancel entry point.

---

### Recommendation

1. Call `check_psbt_chain_specific` (or an equivalent Orchard-aware validator) inside `check_psbt_output_all_change_address` whenever the PSBT carries an Orchard bundle, regardless of `is_cancel`.
2. Subtract the Orchard bundle amount from `input_amount` before computing `gas_fee`, mirroring the accounting done in `check_withdraw_psbt` via `add_extra_outputs`.
3. For cancel-active-UTXO-management specifically, assert `!psbt.has_orchard_bundle()` — a consolidation/split cancel should never pay a shielded recipient.

---

### Proof of Concept

```
1. An active UTXO management tx is pending with vutxos summing to V zatoshis,
   original max_gas_fee = F.

2. Wait until block_timestamp − create_time_sec > max_btc_tx_pending_sec.

3. Craft cancel PSBT:
   - Transparent inputs:  the same UTXOs (total V)
   - Transparent outputs: N outputs each to bridge change address,
                          each just above unhealthy_utxo_amount,
                          total transparent_out = T  (T << V)
   - Orchard bundle:      one action paying attacker's shielded address,
                          amount X = V − T − actual_fee
                          (choose X s.t. X − F ≤ cur_available_protocol_fee)

4. Submit via the public cancel-active-UTXO-management entry point.

5. check_psbt_output_all_change_address(is_cancel=true):
   - output_amount = T  (transparent only, all valid bridge change)
   - gas_fee = V − T   (includes X; range check skipped)
   - Orchard bundle: never validated

6. additional_gas_fee = (V−T) − F = X + actual_fee − F ≤ cur_available_protocol_fee → passes.

7. PSBT stored; bridge signs; transaction broadcast.
   Attacker receives X ZEC in their Orchard shielded address.
   Bridge accounting records V−T as gas fees.
```

### Citations

**File:** contracts/satoshi-bridge/src/rbf/cancel_active_utxo_management.rs (L7-18)
```rust
    pub fn check_cancel_active_utxo_management_rbf_psbt_valid(
        &self,
        original_tx_btc_pending_info: &BTCPendingInfo,
        cancel_active_utxo_management_rbf_psbt: &PsbtWrapper,
    ) -> (u128, u128) {
        let (actual_received_amount, gas_fee) = self.check_psbt_output_all_change_address(
            cancel_active_utxo_management_rbf_psbt,
            &original_tx_btc_pending_info.vutxos,
            true,
            true,
        );
        (actual_received_amount, gas_fee)
```

**File:** contracts/satoshi-bridge/src/rbf/cancel_active_utxo_management.rs (L30-34)
```rust
        require!(
            nano_to_sec(env::block_timestamp()) - original_tx_btc_pending_info.create_time_sec
                > self.internal_config().max_btc_tx_pending_sec,
            "Please wait user rbf"
        );
```

**File:** contracts/satoshi-bridge/src/rbf/cancel_active_utxo_management.rs (L45-70)
```rust
        let (actual_received_amount, gas_fee) = self
            .check_cancel_active_utxo_management_rbf_psbt_valid(
                original_tx_btc_pending_info,
                &cancel_active_utxo_management_rbf_psbt,
            );
        btc_pending_info.gas_fee = gas_fee;
        btc_pending_info.burn_amount = gas_fee;
        btc_pending_info.actual_received_amount = actual_received_amount;
        // Ensure that the RBF transaction pays more gas than the previous transaction.
        let max_gas_fee = original_tx_btc_pending_info.get_max_gas_fee();
        let additional_gas_amount = gas_fee.saturating_sub(max_gas_fee);
        require!(additional_gas_amount > 0, "No gas increase.");
        require!(
            self.data().cur_available_protocol_fee >= additional_gas_amount,
            "Insufficient protocol fee"
        );
        self.data_mut().cur_available_protocol_fee -= additional_gas_amount;
        self.data_mut().cur_reserved_protocol_fee += additional_gas_amount;
        self.internal_unwrap_mut_btc_pending_info(&original_btc_pending_verify_id)
            .do_cancel(gas_fee, 0);
        self.set_rbf_pending_info(
            &original_btc_pending_verify_id,
            btc_pending_info,
            cancel_active_utxo_management_rbf_psbt,
            true,
        )
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L127-151)
```rust
        let output_amount = psbt
            .get_output()
            .iter()
            .map(|v| {
                if force_healthy_output {
                    require!(
                        v.value.to_sat() > config.unhealthy_utxo_amount
                            && u128::from(v.value.to_sat()) <= config.max_change_amount,
                        "The output amount is not in the valid range"
                    );
                } else {
                    require!(
                        u128::from(v.value.to_sat()) >= config.min_change_amount
                            && u128::from(v.value.to_sat()) <= config.max_change_amount,
                        "The output amount is not in the valid range"
                    );
                }
                require!(
                    v.script_pubkey == withdraw_change_address_script_pubkey,
                    "Invalid output script_pubkey"
                );
                u128::from(v.value.to_sat())
            })
            .sum::<u128>();
        let gas_fee = input_amount - output_amount;
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L152-160)
```rust
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

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L192-212)
```rust
    pub(crate) fn check_psbt_chain_specific(
        &self,
        psbt: &PsbtWrapper,
        gas_fee: u128,
        target_btc_address: String,
    ) {
        let min_fee = psbt.get_min_fee();
        require!(
            gas_fee >= min_fee.into_u64() as u128,
            format!(
                "Invalid gas fee ({}). min fee = {}.",
                gas_fee,
                min_fee.into_u64()
            )
        );

        // For withdrawals with Orchard bundle, calculate the expected net amount after fees
        if psbt.has_orchard_bundle() {
            psbt.validate_orchard_bundle(target_btc_address, self.internal_config().chain.clone());
        }
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L449-451)
```rust
            digester.digest_orchard(self.orchard.as_ref().map(|b| &b.bundle)),
        )
    }
```
