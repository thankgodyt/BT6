I have all the code needed to evaluate this claim. Let me trace the exact state machine.

---

## State Trace After `execute_refund` Succeeds

`finalize_refund_with_psbt` performs these writes atomically: [1](#0-0) 

1. `require_pending_sign_capacity(&caller)` — passes (slot was empty, default max = 1)
2. Inserts `btc_pending_info` into `btc_pending_infos`
3. Inserts `btc_pending_id` into `account.btc_pending_sign_ids` — **slot now full**
4. Inserts `utxo_storage_key` into `verified_deposit_utxo`
5. Sets `refund_request.executed = true` and re-inserts the request

Post-state: `executed=true`, `verified_deposit_utxo` contains the key, `btc_pending_sign_ids` is at capacity (1/1).

---

## Three Escape Hatches — All Blocked for Unprivileged Callers

**Escape 1: Re-call `execute_refund`**

`load_refund_request_for_execute` passes the UTXO check because `executed==true`: [2](#0-1) 

But `finalize_refund_with_psbt` then calls `require_pending_sign_capacity`: [3](#0-2) 

Default `get_max_pending_sign_txs` returns `1`: [4](#0-3) 

`pending_sign_count() = 1`, `max = 1`, so `1 < 1` is false → **reverts "Too many pending sign transactions"**.

**Escape 2: `remove_refund_pending_tx_id`** [5](#0-4) 

The refund request is still in `refund_requests` (with `executed=true`), so `contains_key` returns true → **reverts "refund request still active"**.

Additionally, `remove_refund_pending_tx_id` is gated by `#[trusted_relayer]`, so an unprivileged user cannot even reach this check: [6](#0-5) 

**Escape 3: `reject_refund`** [7](#0-6) 

`executed==true` → `is_already_deposited = false`. Unprivileged caller is not `is_privileged` → **reverts "Only DAO/Operator can reject"**.

---

## Is the Deadlock Real?

The code comment explicitly documents the re-execution invariant: [8](#0-7) 

And in `load_refund_request_for_execute`: [9](#0-8) 

The invariant is broken. After a consensus branch change (reorg), during the window between `execute_refund` completing and the chain-signature callback moving the pending info from `btc_pending_sign_ids` to `btc_pending_verify_list`, all three escape hatches revert for an unprivileged caller. The deposit UTXO is stuck:

- Cannot be refunded (slot full)
- Cannot be deposited (`verified_deposit_utxo` blocks it)
- Cannot be rejected (executed=true blocks permissionless reject)

Resolution requires DAO/Operator to call `reject_refund` (privileged path) or `set_pending_tx_limit` to raise the cap.

---

### Title
Documented re-execution path after consensus branch change is permanently blocked for unprivileged callers, locking deposit UTXO without operator intervention — (`contracts/satoshi-bridge/src/refund.rs`)

### Summary
After `execute_refund` succeeds, the caller's `btc_pending_sign_ids` slot is filled and `refund_request.executed` is set to `true`. If a Bitcoin reorg invalidates the refund transaction before the chain-signature callback completes (moving the pending info out of `btc_pending_sign_ids`), all three self-service escape hatches revert for an unprivileged caller, permanently locking the deposit UTXO until DAO/Operator intervenes.

### Finding Description
`finalize_refund_with_psbt` unconditionally calls `require_pending_sign_capacity` before inserting the new pending info. It does not check whether the existing pending info in the slot belongs to a prior execution of the same refund (which should be replaceable). The re-execution path documented in the code comments is therefore unreachable for any unprivileged user who has already consumed their sole pending-sign slot.

The three escape hatches all fail:
1. `execute_refund` → `require_pending_sign_capacity` reverts (slot full)
2. `remove_refund_pending_tx_id` → reverts "refund request still active" (request still in map with `executed=true`), and is additionally gated by `#[trusted_relayer]`
3. `reject_refund` → `is_already_deposited = false` because `executed==true` suppresses the permissionless path; unprivileged caller reverts

### Impact Explanation
The deposit UTXO is locked in a state where neither the original refund tx can confirm (it was reorganized away) nor a replacement can be submitted. The user's BTC is inaccessible until a DAO/Operator account calls `reject_refund` or raises the pending-tx limit. This matches **Medium** impact: attacker-triggered temporary locking of bridged funds requiring operator intervention.

### Likelihood Explanation
Bitcoin reorgs are uncommon but real, especially for deposits near the confirmation threshold. The vulnerable window is the time between `execute_refund` completing and the chain-signature callback moving the pending info from `btc_pending_sign_ids` to `btc_pending_verify_list`. Any user who calls `execute_refund` during a reorg is affected. Likelihood is **Low-to-Medium** (requires a reorg in a specific window).

### Recommendation
In `finalize_refund_with_psbt`, before calling `require_pending_sign_capacity`, check whether the account already holds a pending-sign entry for a prior execution of this same refund (i.e., a `BTCPendingInfo` whose UTXO storage key matches `utxo_storage_key`). If so, remove the stale entry first, then insert the replacement — bypassing the capacity check for this specific re-execution case. Alternatively, skip the capacity check entirely when `refund_request.executed == true`.

### Proof of Concept
```
1. User calls execute_refund(utxo_key) → succeeds
   State: executed=true, verified_deposit_utxo={utxo_key}, btc_pending_sign_ids={id1}

2. Bitcoin reorg occurs before chain-signature callback completes
   (id1 is still in btc_pending_sign_ids, slot full)

3. User calls execute_refund(utxo_key) again
   → load_refund_request_for_execute: passes (executed==true bypasses UTXO check)
   → finalize_refund_with_psbt: require_pending_sign_capacity → REVERT "Too many pending sign transactions"

4. User calls remove_refund_pending_tx_id(id1)
   → REVERT "refund request still active" (request still in map)
   (also blocked by #[trusted_relayer])

5. User calls reject_refund(utxo_key)
   → executed=true → is_already_deposited=false → REVERT "Only DAO/Operator can reject"

6. Deadlock: only acl_has_role(DAO/Operator) breaks it via privileged reject_refund
```

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L250-258)
```rust
        // Block only if the UTXO was claimed by a deposit. If it was claimed by
        // our own refund (executed == true, which also set verified_deposit_utxo),
        // re-running execute_refund is allowed — re-creating the refund tx, e.g.
        // after a consensus branch change.
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L342-401)
```rust
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

**File:** contracts/satoshi-bridge/src/account.rs (L105-111)
```rust
    pub fn get_max_pending_sign_txs(&self, account_id: &AccountId) -> u32 {
        self.data()
            .pending_tx_limits
            .get(account_id)
            .copied()
            .unwrap_or(1)
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L553-568)
```rust
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L622-626)
```rust
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn remove_refund_pending_tx_id(&mut self, tx_id: String) {
        self.internal_remove_refund_pending_tx_id(tx_id);
    }
```
