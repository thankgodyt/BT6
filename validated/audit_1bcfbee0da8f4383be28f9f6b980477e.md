### Title
Refund Rejection Can Be Front-Run by `execute_refund`, Enabling Theft of Unfinalized BTC Deposits — (File: `contracts/satoshi-bridge/src/api/bridge.rs`, `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`execute_refund` is callable by any unprivileged NEAR account once `unsafe_refund_timelock_sec` elapses. If the DAO/Operator broadcasts `reject_refund` to cancel a suspicious refund request, an attacker can front-run it with `execute_refund`. Even if `reject_refund` subsequently executes and removes the `RefundRequest`, the `BTCPendingInfo` created by `execute_refund` persists in contract state and can be signed and broadcast — sending BTC to the attacker-controlled address.

---

### Finding Description

**Step 1 — Attacker submits a refund request for a victim's unfinalized deposit.**

`request_refund` is permissionless: any NEAR account can call it for any confirmed BTC deposit that has not yet been finalized via `verify_deposit`. When `deposit_msg.refund_address` is `None`, the caller freely supplies any `refund_address` they choose. [1](#0-0) 

The only validation is that the output script matches the deposit address derived from `deposit_msg`. The `deposit_msg` is public (emitted in bridge events when `get_user_deposit_address` is called), so an attacker can reconstruct it for any observed deposit.

**Step 2 — `unsafe_refund_timelock_sec` is the sole protection.**

When `deposit_msg.refund_address` is `None`, `resolve_execute_refund_timelock` applies the longer `unsafe_refund_timelock_sec` — explicitly described as giving DAO/Operator time to reject suspicious requests before execution becomes possible. [2](#0-1) 

**Step 3 — After the timelock, `execute_refund` is callable by anyone.**

`execute_refund` carries no role restriction beyond `#[pause]`. Once the timelock elapses, any unprivileged account can call it. [3](#0-2) 

**Step 4 — DAO/Operator submits `reject_refund`; attacker front-runs with `execute_refund`.**

The DAO/Operator, noticing the suspicious request after the timelock has passed, broadcasts `reject_refund`. Before that transaction is ordered, the attacker submits `execute_refund`. On NEAR, intra-block transaction ordering is not guaranteed; the attacker's transaction can be ordered first.

`execute_refund` calls `finalize_refund_with_psbt`, which:
- Creates a `BTCPendingInfo` owned by the attacker (the `caller`)
- Inserts the UTXO into `verified_deposit_utxo`
- Marks the `RefundRequest` as `executed = true` (but keeps it) [4](#0-3) 

**Step 5 — `reject_refund` succeeds but leaves `BTCPendingInfo` intact.**

`reject_refund` (DAO/Operator) removes the `RefundRequest` from `refund_requests`. However, `internal_reject_refund` does **not** remove the `BTCPendingInfo` that was already created. [5](#0-4) 

The `BTCPendingInfo` — containing the PSBT paying the attacker's BTC address — remains in `btc_pending_infos` and in the attacker's `btc_pending_sign_ids`.

**Step 6 — Attacker signs and broadcasts.**

The attacker calls `sign_btc_transaction` on the surviving `BTCPendingInfo`. The MPC network signs the PSBT. The attacker broadcasts the signed transaction to Bitcoin. BTC is transferred to the attacker's address. The victim's deposit is stolen.

`remove_refund_pending_tx_id` exists to clean up stale pending infos, but it is a separate, manually-triggered call that requires the DAO/Operator to know the pending ID and act before the attacker signs — a race the attacker wins by acting immediately after `execute_refund`. [6](#0-5) 

---

### Impact Explanation

An unprivileged attacker can steal BTC from any unfinalized deposit whose `deposit_msg` is observable on-chain (all of them, since `get_user_deposit_address` emits events). The `unsafe_refund_timelock_sec` protection is fully bypassed: even if the DAO/Operator correctly identifies and rejects the malicious request, the `BTCPendingInfo` survives and the BTC transfer proceeds. This is **Critical** — direct theft of user BTC funds held by the bridge.

---

### Likelihood Explanation

**Medium-High.** The attacker's entry path requires only:
1. Observing a confirmed BTC deposit that has not been finalized (common during relayer downtime or user inactivity).
2. Reconstructing `deposit_msg` from public bridge events.
3. Waiting for `unsafe_refund_timelock_sec` to elapse.
4. Submitting `execute_refund` in the same NEAR block as the DAO/Operator's `reject_refund`.

Steps 1–3 are trivially automatable. Step 4 is feasible because NEAR mempool monitoring is possible and intra-block ordering is not deterministic from the attacker's perspective — but the attacker can also simply call `execute_refund` the moment the timelock expires, before the DAO/Operator reacts, without needing to observe the rejection transaction at all.

---

### Recommendation

1. **`reject_refund` must atomically cancel any associated `BTCPendingInfo`.** When `executed == true`, `internal_reject_refund` should look up and remove the `BTCPendingInfo` whose UTXO key matches `utxo_storage_key`, preventing the in-flight signing from proceeding.

2. **Alternatively, gate `execute_refund` on privileged callers when `deposit_msg.refund_address` is `None`.** If the refund address was not pre-authorized in the deposit message, only DAO/Operator/RefundOperator should be able to execute — eliminating the permissionless execution window that enables the front-run.

3. **At minimum, document that `reject_refund` does not cancel an already-executed refund** and require operators to also call `remove_refund_pending_tx_id` immediately after rejection when `executed == true`.

---

### Proof of Concept

```
1. Victim deposits 1 BTC to bridge deposit address derived from:
   deposit_msg = { recipient_id: "victim.near", refund_address: None, ... }
   verify_deposit is never called (relayer is down).

2. Attacker observes the deposit on Bitcoin and reconstructs deposit_msg
   from bridge LogDepositAddress events.

3. Attacker calls:
   request_refund(deposit_msg, refund_address="attacker_btc_addr", tx_bytes, vout, proof)
   → RefundRequest stored with unsafe_refund_timelock_sec (e.g. 7 days).

4. After 7 days, DAO/Operator notices and broadcasts:
   reject_refund(utxo_storage_key)

5. Attacker monitors NEAR and submits in the same block (or earlier):
   execute_refund(utxo_storage_key)
   → BTCPendingInfo created, owner = attacker, refund_address = "attacker_btc_addr"
   → verified_deposit_utxo updated
   → RefundRequest.executed = true

6. reject_refund executes (possibly after execute_refund):
   → RefundRequest removed from refund_requests
   → BTCPendingInfo NOT removed (internal_reject_refund only removes the request)

7. Attacker calls sign_btc_transaction(btc_pending_id, sign_index=0)
   → MPC signs the PSBT paying "attacker_btc_addr"

8. Attacker broadcasts signed BTC transaction.
   → 1 BTC (minus gas fee) transferred to attacker.
   → Victim's deposit is stolen.
```

Key code path confirming `BTCPendingInfo` survives rejection: [7](#0-6) [5](#0-4) [8](#0-7)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L187-196)
```rust
    pub(crate) fn internal_reject_refund(&mut self, utxo_storage_key: String) {
        require!(
            self.data_mut()
                .refund_requests
                .remove(&utxo_storage_key)
                .is_some(),
            "Refund request not found"
        );
        Event::RefundRejected { utxo_storage_key }.emit();
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L223-227)
```rust
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L344-401)
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L544-568)
```rust
    pub fn reject_refund(&mut self, utxo_storage_key: String) {
        let caller = env::predecessor_account_id();
        let is_privileged = self.acl_has_role(Role::DAO.into(), caller.clone())
            || self.acl_has_role(Role::Operator.into(), caller);
        // `execute_refund` also inserts the UTXO into `verified_deposit_utxo` (to block a
        // later deposit) while keeping the request with `executed == true`. That membership
        // must NOT open the permissionless reject path, otherwise anyone could cancel an
        // in-flight refund — so only treat the UTXO as "already deposited" when the request
        // was not executed by us, i.e. a real `verify_deposit` finalized it.
        let executed = self
            .data()
            .refund_requests
            .get(&utxo_storage_key)
            .map(|r| RefundRequest::from(r).executed)
            .unwrap_or(false);
        let is_already_deposited = !executed
            && self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key);
        require!(
            is_privileged || is_already_deposited,
            "Only DAO/Operator can reject, or UTXO must be already verified via deposit"
        );
        self.internal_reject_refund(utxo_storage_key);
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
