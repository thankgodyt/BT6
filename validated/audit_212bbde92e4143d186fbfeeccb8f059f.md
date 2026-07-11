I have enough information to analyze this fully. Let me trace the complete execution path.

**Execution path trace:**

**1. Creating multiple RBF entries** — `internal_withdraw_rbf` in `rbf/withdraw.rs` creates a `WithdrawUserRbf` entry in `PendingSign` state. `set_rbf_pending_info` enforces `rbf_txs.len() <= rbf_num_limit`, so up to `rbf_num_limit` RBF entries can exist for the same original tx. Each is a separate `btc_pending_id`.

**2. Advancing to PendingVerify** — Each RBF entry is independently signed by the MPC network and advanced to `PendingVerify`. There is no guard preventing multiple RBF entries from simultaneously holding `PendingVerify` state.

**3. Submitting `verify_withdraw` for multiple entries** — `internal_verify_withdraw_entry` checks: [1](#0-0) 

- The current tx is in `PendingVerify` ✓ (each entry has its own state)
- The original tx still exists ✓ (it hasn't been removed yet)

There is **no check** that any other RBF sibling is already in the verification pipeline. Both `verify_withdraw(rbf_1)` and `verify_withdraw(rbf_2)` can be submitted before either callback runs, dispatching two concurrent light-client verification promises.

**4. Both `internal_verify_withdraw_callback` invocations succeed** — Each callback checks only its own `tx_id`'s state: [2](#0-1) 

Since `rbf_1` and `rbf_2` are separate map entries, both pass `assert_pending_verify()`. Both call `to_pending_burn_stage()` on their respective entries and dispatch `verify_withdraw_burn_promise`.

**5. Both burn calls to nBTC are dispatched** — `verify_withdraw_burn_promise` calls `ext_nbtc::burn(burn_amount)` for each entry: [3](#0-2) 

Both burns execute against the user's nBTC balance.

**6. First burn callback (`rbf_1`) succeeds** — `verify_withdraw_burn_callback` removes `rbf_txs[original_tx_id]`, removes `btc_pending_infos[original_tx_id]`, and removes `btc_pending_infos[rbf_1]`: [4](#0-3) 

**7. Second burn callback (`rbf_2`) panics** — `verify_withdraw_burn_callback` for `rbf_2` calls `internal_remove_btc_pending_info(original_tx_id)`, but `original_tx_id` was already removed in step 6: [5](#0-4) 

`internal_remove_btc_pending_info` panics with "BTC pending info not exist": [6](#0-5) 

**Critical consequence**: In NEAR, when a callback panics, state changes in the callback are rolled back, but the prior cross-contract call (the `burn`) is **not rolled back**. The nBTC burned for `rbf_2` is permanently destroyed. `rbf_2` reverts to `PendingBurn` state with no cleanup path (original_tx is gone, `rbf_txs` is gone), leaving it permanently stuck.

---

### Title
Concurrent `verify_withdraw` for multiple RBF siblings causes double-burn of user nBTC with stuck PendingBurn state — (`contracts/satoshi-bridge/src/btc_light_client/withdraw.rs`)

### Summary
`internal_verify_withdraw_entry` lacks a guard preventing multiple sibling RBF entries from entering the verification pipeline simultaneously. An unprivileged user can advance up to `rbf_num_limit` `WithdrawUserRbf` entries to `PendingVerify` and submit `verify_withdraw` for all of them before any callback resolves. Each callback independently passes its own `assert_pending_verify()` check, dispatches a burn call, and the second burn's callback panics on a missing `original_tx_id`, leaving nBTC permanently destroyed without BTC delivery.

### Finding Description
The missing invariant is in `internal_verify_withdraw_entry`:

```rust
// withdraw.rs:45-52
let btc_pending_info = self.internal_unwrap_btc_pending_info(&tx_id);
btc_pending_info.assert_withdraw_related_pending_verify_tx();
if let Some(original_tx_id) = btc_pending_info.get_original_tx_id() {
    require!(
        self.check_btc_pending_info_exists(original_tx_id),
        "original tx already verified"
    );
}
```

The check only verifies (a) the current entry is `PendingVerify` and (b) the original tx still exists. It does **not** verify that no sibling RBF entry is already in `PendingBurn` or has an in-flight verification promise. Because NEAR cross-contract calls are asynchronous, both `verify_withdraw(rbf_1)` and `verify_withdraw(rbf_2)` can be submitted before either callback runs, satisfying both checks for both entries.

The `internal_verify_withdraw_callback` compounds this by checking only the specific `tx_id`'s state: [2](#0-1) 

There is no cross-sibling check. Both callbacks advance their respective entries to `PendingBurn` and dispatch burns.

In `verify_withdraw_burn_callback`, the first successful callback removes `original_tx_id` from `btc_pending_infos`. The second callback then panics at: [5](#0-4) 

The panic rolls back the callback's state changes but cannot undo the already-executed `ext_nbtc::burn`. The second RBF entry is stuck in `PendingBurn` permanently.

### Impact Explanation
- User's nBTC is burned N times (once per concurrently verified RBF entry) for a single BTC withdrawal.
- Only one BTC transaction is broadcast; the extra burns are unrecoverable.
- nBTC total supply is permanently reduced below the BTC backing, violating the 1:1 peg invariant.
- The extra RBF entries are stuck in `PendingBurn` with no cleanup path (original_tx and `rbf_txs` already removed), requiring operator intervention.

**Impact: Medium** — permanent burning below backed supply, broken callback rollback, stuck bridge state.

### Likelihood Explanation
The path is fully public: `internal_withdraw_rbf` is callable by any user who owns the withdrawal, the MPC network signs any valid PSBT, and `verify_withdraw` is a public entry. A user could trigger this accidentally (submitting verify for multiple RBF entries when they see multiple confirmations) or intentionally. `rbf_num_limit` bounds the multiplier but does not prevent the race.

### Recommendation
In `internal_verify_withdraw_entry`, before dispatching the light-client verification, assert that no sibling RBF entry for the same original tx is already in `PendingBurn` state. Concretely:

1. When an RBF entry enters the verification pipeline (i.e., `verify_withdraw` is called), mark the original tx or the `rbf_txs` set as "verification in progress" and reject any further `verify_withdraw` calls for siblings until the first resolves.
2. Alternatively, enforce a single-active-verification invariant: when `verify_withdraw(rbf_X)` is called, check that no other entry in `rbf_txs[original_tx_id]` is in `PendingBurn` state.
3. In `internal_verify_withdraw_callback`, use `internal_remove_btc_pending_info` defensively (check existence before removing) so that a panic does not leave burned nBTC unaccounted.

### Proof of Concept
```
1. User initiates withdrawal → original_tx (PendingVerify)
2. User calls internal_withdraw_rbf(original_tx) → rbf_1 (PendingSign)
3. User calls internal_withdraw_rbf(original_tx) → rbf_2 (PendingSign)
4. MPC signs rbf_1 → rbf_1 (PendingVerify)
5. MPC signs rbf_2 → rbf_2 (PendingVerify)
6. User submits verify_withdraw(rbf_1) → dispatches light-client call A
   [check: rbf_1 is PendingVerify ✓, original_tx exists ✓]
7. User submits verify_withdraw(rbf_2) → dispatches light-client call B
   [check: rbf_2 is PendingVerify ✓, original_tx exists ✓]
   (no state change between 6 and 7 blocks either call)
8. Callback A: rbf_1 → PendingBurn, burn(rbf_1.burn_amount) dispatched
9. Callback B: rbf_2 → PendingBurn, burn(rbf_2.burn_amount) dispatched
10. burn_callback(rbf_1) succeeds:
    - rbf_txs[original_tx] removed
    - btc_pending_infos[original_tx] removed
    - btc_pending_infos[rbf_1] removed
11. burn_callback(rbf_2) succeeds at nBTC level (burn already executed), then:
    - internal_remove_btc_pending_info(original_tx) → PANIC (already removed)
    - Callback state rolled back; rbf_2 stuck in PendingBurn
    - rbf_2.burn_amount of nBTC permanently destroyed with no BTC sent
Assert: user's nBTC reduced by rbf_1.burn_amount + rbf_2.burn_amount,
        but only one BTC tx broadcast.
```

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/withdraw.rs (L45-52)
```rust
        let btc_pending_info = self.internal_unwrap_btc_pending_info(&tx_id);
        btc_pending_info.assert_withdraw_related_pending_verify_tx();
        if let Some(original_tx_id) = btc_pending_info.get_original_tx_id() {
            require!(
                self.check_btc_pending_info_exists(original_tx_id),
                "original tx already verified"
            );
        }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/withdraw.rs (L77-81)
```rust
        self.internal_unwrap_btc_pending_info(&tx_id)
            .assert_pending_verify();
        self.internal_unwrap_mut_btc_pending_info(&tx_id)
            .to_pending_burn_stage();
        self.verify_withdraw_burn_promise(tx_id).into()
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L17-29)
```rust
        ext_nbtc::ext(config.nbtc_account_id.clone())
            .with_static_gas(GAS_FOR_BURN_CALL)
            .burn(
                btc_pending_info.account_id.clone(),
                btc_pending_info.burn_amount.into(),
                env::signer_account_id(),
                relayer_fee.into(),
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_WITHDRAW_BURN_CALL_BACK)
                    .verify_withdraw_burn_callback(tx_id, protocol_fee.into(), relayer_fee.into()),
            )
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L102-143)
```rust
            if let Some(original_tx_id) = btc_pending_info.get_original_tx_id() {
                self.data_mut().rbf_txs.remove(original_tx_id);
                self.internal_unwrap_mut_account(&btc_pending_info.account_id)
                    .btc_pending_verify_list
                    .remove(original_tx_id);
                let original_tx_btc_pending_info =
                    self.internal_remove_btc_pending_info(original_tx_id);
                if let Some(U128(cancel_rbf_reserved)) =
                    original_tx_btc_pending_info.get_cancel_rbf_reserved()
                {
                    if cancel_rbf_reserved > 0 {
                        self.data_mut().cur_reserved_protocol_fee -= cancel_rbf_reserved;
                        if btc_pending_info.is_cancel_withdraw_rbf() {
                            self.data_mut().acc_protocol_fee_for_gas += cancel_rbf_reserved;
                        } else {
                            self.data_mut().cur_available_protocol_fee += cancel_rbf_reserved;
                        }
                    }
                }
            } else {
                self.internal_unwrap_mut_account(&btc_pending_info.account_id)
                    .btc_pending_verify_list
                    .remove(&tx_id);
                self.data_mut().rbf_txs.remove(&tx_id);

                if let Some(U128(cancel_rbf_reserved)) = btc_pending_info.get_cancel_rbf_reserved()
                {
                    if cancel_rbf_reserved > 0 {
                        self.data_mut().cur_reserved_protocol_fee -= cancel_rbf_reserved;
                        self.data_mut().cur_available_protocol_fee += cancel_rbf_reserved;
                    }
                }
            }
            if protocol_fee.0 > 0 {
                self.data_mut().acc_collected_protocol_fee += protocol_fee.0;
                self.data_mut().cur_available_protocol_fee += protocol_fee.0;
            }
            if refund > 0 {
                self.internal_transfer_nbtc(&btc_pending_info.account_id, refund)
                    .detach();
            }
            self.internal_remove_btc_pending_info(&tx_id);
```

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L395-401)
```rust
    pub fn internal_remove_btc_pending_info(&mut self, btc_pending_id: &String) -> BTCPendingInfo {
        self.data_mut()
            .btc_pending_infos
            .remove(btc_pending_id)
            .expect("BTC pending info not exist")
            .into()
    }
```
