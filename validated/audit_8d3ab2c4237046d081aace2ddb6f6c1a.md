### Title
Concurrent `execute_refund` Calls Exploit Async State-Update Window to Create Duplicate MPC Signing Requests and Stuck Bridge State - (File: contracts/satoshi-bridge/src/refund.rs)

---

### Summary

The public `execute_refund` function performs all pre-execution guard checks against on-chain state that is only updated inside the asynchronous callback (`finalize_refund_with_psbt`). Because NEAR cross-contract calls are asynchronous, a second `execute_refund` call submitted before the first callback settles will pass every guard, trigger a second MPC signing request for the same deposit UTXO, and insert a second `BTCPendingInfo` entry into bridge state. Only one of the resulting Bitcoin transactions can confirm on-chain; the other is a permanent double-spend, leaving the bridge with an irrecoverable stale pending entry until an operator manually invokes `remove_refund_pending_tx_id`.

---

### Finding Description

`execute_refund` is a public, payable function gated only by the `#[pause]` macro: [1](#0-0) 

It delegates immediately to `internal_execute_refund`, which (following the same pattern as every other bridge operation) makes an external cross-contract call — to the MPC chain-signatures service — and schedules a callback. The state-mutating work (setting `executed = true`, inserting the UTXO key into `verified_deposit_utxo`, and inserting the new `BTCPendingInfo`) all happens inside `finalize_refund_with_psbt`, which runs only after that callback resolves: [2](#0-1) 

The sole guard that is supposed to prevent duplicate execution is inside `load_refund_request_for_execute`: [3](#0-2) 

```rust
require!(
    !self.data().verified_deposit_utxo.contains(utxo_storage_key)
        || refund_request.executed,
    "UTXO already verified via deposit, cannot refund"
);
```

Both conditions (`verified_deposit_utxo` membership and `executed`) are written only inside `finalize_refund_with_psbt`. During the entire window between the initial `execute_refund` call and its callback, neither condition is true, so any concurrent second call passes the guard identically.

Furthermore, `finalize_refund_with_psbt` uses `env::predecessor_account_id()` as the owner of the new `BTCPendingInfo`: [4](#0-3) 

The per-account pending-sign capacity check (`require_pending_sign_capacity`) is therefore scoped to the caller's account. Two different NEAR accounts calling `execute_refund` concurrently each have independent capacity, so both pass and each inserts its own `BTCPendingInfo` entry: [5](#0-4) 

The duplicate-key guard inside `finalize_refund_with_psbt` only blocks identical PSBT IDs: [6](#0-5) 

Because each call builds a fresh PSBT (different timestamp, potentially different inputs), the IDs differ and both inserts succeed.

---

### Impact Explanation

Two (or more) concurrent `execute_refund` calls for the same refund request each:

1. Trigger a separate MPC chain-signature request, consuming signing resources.
2. Insert a separate `BTCPendingInfo` entry into `btc_pending_infos`.
3. Broadcast a separate Bitcoin transaction spending the same deposit UTXO.

Only one Bitcoin transaction can confirm; the others are invalid double-spends. The bridge is left with stale `BTCPendingInfo` entries that cannot be finalized via `verify_refund_finalize` (which requires on-chain confirmation) and cannot be removed via `remove_refund_pending_tx_id` until the refund request itself is deleted by a successful `verify_refund_finalize_callback`: [7](#0-6) 

Until an operator manually calls `remove_refund_pending_tx_id` after the winning transaction confirms, the stale entries occupy bridge state and the affected accounts' pending-sign slots, potentially blocking legitimate future withdrawals for those accounts.

This matches the **Medium** allowed impact: *stuck bridge state requiring operator intervention*.

---

### Likelihood Explanation

`execute_refund` is fully public and callable by any NEAR account after the timelock elapses. The only cost to an attacker is the `required_balance_for_execute_refund()` storage deposit per call. An attacker monitoring the bridge can observe a pending refund request, wait for the timelock, and submit two concurrent calls from two accounts in the same NEAR block. No privileged access, leaked keys, or third-party compromise is required.

---

### Recommendation

Before making the external MPC signing call inside `internal_execute_refund`, atomically mark the refund request as in-progress — for example, by inserting the UTXO key into `verified_deposit_utxo` or by adding a dedicated `in_progress` flag to `RefundRequest`. Roll back this marker in the callback if the external call fails. This mirrors the check-effects-interactions pattern and closes the async window entirely.

---

### Proof of Concept

1. A refund request for UTXO key `K` exists with `executed = false`; the timelock has elapsed.
2. Account `A` calls `execute_refund(K, …)` with the required deposit attached.
   - `load_refund_request_for_execute`: `verified_deposit_utxo` does not contain `K`, `executed = false` → guard passes.
   - `internal_execute_refund` fires an MPC signing cross-contract call; callback is scheduled.
   - **State is unchanged at this point.**
3. Before the callback from step 2 settles, account `B` calls `execute_refund(K, …)`.
   - Same guard check: `verified_deposit_utxo` still does not contain `K`, `executed` still `false` → guard passes.
   - A second MPC signing call is fired; a second callback is scheduled.
4. Callback for `A` resolves → `finalize_refund_with_psbt` runs:
   - Inserts `BTCPendingInfo` with ID `P_A`.
   - Sets `executed = true`, inserts `K` into `verified_deposit_utxo`.
5. Callback for `B` resolves → `finalize_refund_with_psbt` runs again:
   - `P_B ≠ P_A` (different PSBT), so the duplicate-key require passes.
   - Inserts a second `BTCPendingInfo` with ID `P_B`.
   - Overwrites `executed = true` (already true) and re-inserts `K` (idempotent).
6. Two signed Bitcoin transactions exist for the same UTXO. Only one confirms. The bridge holds a permanently stale `BTCPendingInfo` for the losing transaction, requiring operator cleanup.

### Citations

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

**File:** contracts/satoshi-bridge/src/refund.rs (L254-258)
```rust
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L315-402)
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
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L408-431)
```rust
    pub(crate) fn internal_remove_refund_pending_tx_id(&mut self, tx_id: String) {
        let btc_pending_info = self.internal_unwrap_btc_pending_info(&tx_id).clone();
        btc_pending_info.assert_refund_related();

        // A refund spends exactly one deposit UTXO, whose key is the refund request key.
        let utxo_storage_keys = btc_pending_info.get_psbt().get_utxo_storage_keys();
        require!(
            utxo_storage_keys.len() == 1,
            "refund transaction must spend exactly one input"
        );
        require!(
            !self
                .data()
                .refund_requests
                .contains_key(&utxo_storage_keys[0]),
            "refund request still active"
        );

        let account_id = btc_pending_info.account_id.clone();
        self.internal_remove_btc_pending_info(&tx_id);
        let account = self.internal_unwrap_mut_account(&account_id);
        account.btc_pending_sign_ids.remove(&tx_id);
        account.btc_pending_verify_list.remove(&tx_id);
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
