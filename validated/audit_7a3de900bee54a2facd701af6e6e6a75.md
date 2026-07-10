### Title
Any caller can front-run `execute_refund` to block a victim's refund indefinitely — (`contracts/satoshi-bridge/src/refund.rs`, `contracts/satoshi-bridge/src/api/bridge.rs`)

### Summary

`execute_refund` is a permissionless function callable by any NEAR account after the refund timelock elapses. When called, it creates a `BTCPendingInfo` entry keyed by a PSBT ID derived from the fixed refund UTXO. Because the PSBT ID is deterministic for a given refund request, a malicious caller who invokes `execute_refund` first occupies that slot. Every subsequent call by the legitimate victim fails with `"pending info already exist"`, and the DAO has no clean recovery path that does not permanently strand the victim's BTC.

### Finding Description

**Root cause — `execute_refund` is open to any caller:** [1](#0-0) 

No `#[access_control_any]` guard is present. Any NEAR account that attaches the required storage deposit and waits for the timelock can call this function on any pending refund request.

**State created under the attacker's account:**

Inside `finalize_refund_with_psbt`, the `BTCPendingInfo` is stored with `account_id: caller.clone()` and inserted into `btc_pending_infos` keyed by the PSBT ID: [2](#0-1) 

The PSBT ID is derived from the transaction content (the fixed deposit UTXO txid + vout), so it is identical for every call to `execute_refund` on the same refund request.

**Victim's retry is rejected:**

When the victim calls `execute_refund` after the attacker, `load_refund_request_for_execute` passes (because `refund_request.executed == true` satisfies the `verified_deposit_utxo` check): [3](#0-2) 

But `finalize_refund_with_psbt` then tries to insert a `BTCPendingInfo` with the same PSBT ID and panics: [4](#0-3) 

**DAO recovery path is destructive:**

`remove_refund_pending_tx_id` — the only function that can clean up the attacker's stale pending info — requires the refund request to already be absent: [5](#0-4) 

So the DAO must first call `reject_refund` to remove the request. But `internal_reject_refund` does **not** remove the UTXO from `verified_deposit_utxo`: [6](#0-5) 

After rejection + stale-info removal, the UTXO remains in `verified_deposit_utxo` with no refund request and no pending info. `verify_deposit` is also blocked by `verified_deposit_utxo`, and `request_refund_callback` rejects re-registration of the same UTXO: [7](#0-6) 

There is no on-chain function to remove an entry from `verified_deposit_utxo`. The victim's BTC becomes unrecoverable without a contract upgrade.

### Impact Explanation

An unprivileged attacker can permanently lock a victim's BTC in the bridge by spending a small NEAR storage deposit to front-run `execute_refund`. The DAO's only available recovery sequence (reject + remove) leaves the UTXO permanently stranded in `verified_deposit_utxo`, blocking all deposit and refund paths for that UTXO. This constitutes **permanent locking of user funds** — a Critical allowed impact — or at minimum a stuck bridge state requiring operator intervention (Medium).

### Likelihood Explanation

- `execute_refund` is public and requires only the refund timelock to elapse (2 days for pre-authorized addresses, 14 days for unsafe ones) and a small NEAR storage deposit.
- All refund requests and their `utxo_storage_key` values are observable on-chain.
- The attacker needs no privileged role, no leaked key, and no BTC.
- The attack is repeatable: after each DAO cleanup cycle the attacker can re-invoke `execute_refund` on any newly submitted refund request.
- Likelihood is **medium** (requires deliberate targeting and a wait period, but no technical barrier).

### Recommendation

1. **Restrict `execute_refund` to the original depositor or privileged roles**, or at minimum record the authorized executor in the `RefundRequest` at `request_refund` time and enforce it in `execute_refund`.
2. **Add a function to remove a UTXO from `verified_deposit_utxo`** (DAO-only) so the DAO can fully recover from a griefed refund without a contract upgrade.
3. **Decouple `remove_refund_pending_tx_id` from the refund-request existence check**, or add a separate DAO-only `force_remove_refund_pending_tx_id` that does not require the request to be absent, enabling cleanup while keeping the request alive.

### Proof of Concept

1. Alice deposits BTC to a bridge address derived from a `DepositMsg` with `refund_address = Some("bc1q…alice…")`. The relayer never calls `verify_deposit`.
2. Alice calls `request_refund` → `RefundRequest` is stored with `executed = false`.
3. Two days pass (timelock elapses).
4. **Attacker** calls `execute_refund(alice_utxo_key)` with the required storage deposit.
   - `finalize_refund_with_psbt` runs: `BTCPendingInfo` stored under attacker's account, `refund_request.executed = true`, UTXO added to `verified_deposit_utxo`.
5. Attacker does **not** call `sign_btc_transaction`.
6. Alice calls `execute_refund(alice_utxo_key)`:
   - `load_refund_request_for_execute` passes (`executed == true` bypasses the `verified_deposit_utxo` check).
   - `finalize_refund_with_psbt` panics: `"pending info already exist"`.
7. DAO calls `reject_refund(alice_utxo_key)` → refund request removed; UTXO stays in `verified_deposit_utxo`.
8. DAO calls `remove_refund_pending_tx_id(attacker_psbt_id)` → stale pending info removed.
9. Alice calls `request_refund` → panics: `"UTXO already verified via deposit"`.
10. Alice calls `verify_deposit` → panics: `"Already deposit utxo"`.
11. Alice's BTC is permanently locked with no on-chain recovery path.

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

**File:** contracts/satoshi-bridge/src/refund.rs (L254-258)
```rust
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L344-375)
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

**File:** contracts/satoshi-bridge/src/refund.rs (L534-541)
```rust
        // Double-check not finalized (could have been verified between request and callback)
        require!(
            !self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key),
            "UTXO already verified via deposit"
        );
```
