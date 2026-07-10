### Title
Missing Caller Authorization in `execute_refund` Allows Hijacking of Refund Signing Role, Permanently Locking User BTC — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`execute_refund` performs no check that the caller is the original depositor or refund requester. Any NEAR account can call it after the timelock, becoming the exclusive signer for the refund transaction. A malicious actor who calls first and then refuses to sign permanently locks the victim's BTC with no viable DAO recovery path.

---

### Finding Description

`execute_refund` at `contracts/satoshi-bridge/src/api/bridge.rs:582-589` is callable by any NEAR account after the timelock passes — the only guards are `#[pause]` and the storage deposit check inside `resolve_execute_refund_timelock`. [1](#0-0) 

The caller's identity (`env::predecessor_account_id()`) flows into `internal_execute_refund` as `caller`, which passes it directly to `finalize_refund_with_psbt`. [2](#0-1) 

Inside `finalize_refund_with_psbt`, the caller is stored as `account_id` in the `BTCPendingInfo` struct and inserted into the caller's `btc_pending_sign_ids`, giving that account exclusive signing rights over the refund transaction via `sign_btc_transaction`. [3](#0-2) [4](#0-3) 

On Bitcoin, the refund transaction's txid is fully deterministic (same inputs, same outputs, same script). If a malicious actor calls `execute_refund` first, any subsequent call by the legitimate user or DAO fails with `"pending info already exist"` because the txid is already registered.

The DAO's only apparent recovery path — `reject_refund` followed by `remove_refund_pending_tx_id` — permanently destroys the refund request while leaving the UTXO key in `verified_deposit_utxo` (inserted by `finalize_refund_with_psbt`). [5](#0-4) 

A subsequent `request_refund` call then fails inside `request_refund_callback`: [6](#0-5) 

There is no on-chain function to remove entries from `verified_deposit_utxo`. The BTC is permanently locked.

The `resolve_execute_refund_timelock` function only checks the caller's role to decide the *timelock duration*, not to gate access entirely: [7](#0-6) 

The design comment in the documentation ("anyone can call `execute_refund`") confirms the absence of an ownership check is intentional, but the consequence — that the caller becomes the exclusive signer — is not guarded against.

---

### Impact Explanation

**Critical.** A malicious actor can permanently lock a victim's BTC refund funds. The attack requires no privileged access — only the ability to call a public function after the timelock. The BTC remains in the bridge's deposit address with no recovery path: the refund request is destroyed, the UTXO is marked as verified, and no new refund request can be created for the same UTXO.

---

### Likelihood Explanation

**Medium.** The attacker must monitor the bridge contract for `RefundRequested` events and race to call `execute_refund` immediately after the timelock expires. This is straightforward for any NEAR account watching on-chain events. The attacker needs no funds beyond the NEAR storage deposit required by `execute_refund`. The attack is especially practical against the shorter `refund_timelock_sec` path (pre-authorized `refund_address`).

---

### Recommendation

Decouple the signing authority from the caller of `execute_refund`. The `account_id` stored in `BTCPendingInfo` should always be the original depositor (`deposit_msg.recipient_id`), not the arbitrary caller. Alternatively, restrict `execute_refund` so that only the original depositor or a privileged role (DAO/RefundOperator) can call it, analogous to how `withdraw_rbf` enforces ownership via `&original_tx_btc_pending_info.account_id == account_id`: [8](#0-7) 

---

### Proof of Concept

1. Alice deposits BTC and calls `request_refund`. A `RefundRequest` is stored with `executed=false`.
2. The `refund_timelock_sec` elapses.
3. Mallory (any NEAR account) calls `execute_refund(utxo_storage_key, None)` before Alice.
4. `resolve_execute_refund_timelock` passes — no caller identity check, only timelock duration logic.
5. `finalize_refund_with_psbt` stores `BTCPendingInfo { account_id: mallory }`, inserts the btc_pending_id into Mallory's `btc_pending_sign_ids`, inserts the UTXO key into `verified_deposit_utxo`, and sets `refund_request.executed = true`.
6. Alice calls `execute_refund` → `finalize_refund_with_psbt` panics: `"pending info already exist"` (same Bitcoin txid).
7. Mallory refuses to call `sign_btc_transaction`. The refund transaction is never broadcast.
8. DAO calls `reject_refund` → refund request removed. `verified_deposit_utxo` still contains the key.
9. DAO calls `remove_refund_pending_tx_id` → Mallory's `BTCPendingInfo` removed.
10. DAO or Alice calls `request_refund` → `request_refund_callback` panics: `"UTXO already verified via deposit"`.
11. Alice's BTC is permanently locked in the bridge's deposit address with no on-chain recovery mechanism.

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

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L35-43)
```rust
        let caller = env::predecessor_account_id();
        self.finalize_refund_with_psbt(
            caller,
            refund_request,
            psbt,
            refund_amount,
            utxo_storage_key,
        );
        PromiseOrValue::Value(())
```

**File:** contracts/satoshi-bridge/src/refund.rs (L206-228)
```rust
        let caller = env::predecessor_account_id();
        let is_privileged =
            self.acl_has_any_role(vec![Role::DAO.into(), Role::RefundOperator.into()], caller);
        let refund_request: RefundRequest = self
            .data()
            .refund_requests
            .get(utxo_storage_key)
            .expect("Refund request not found")
            .into();
        let config = self.internal_config();
        if refund_request.deposit_msg().refund_address.is_some() {
            // Pre-authorized refund address: privileged users can fast-track.
            if is_privileged {
                0
            } else {
                config.refund_timelock_sec
            }
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L344-346)
```rust
        let btc_pending_info = BTCPendingInfo {
            account_id: caller.clone(),
            btc_pending_id: btc_pending_id.clone(),
```

**File:** contracts/satoshi-bridge/src/refund.rs (L373-375)
```rust
        self.internal_unwrap_mut_account(&caller)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());
```

**File:** contracts/satoshi-bridge/src/refund.rs (L377-381)
```rust
        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());

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

**File:** contracts/satoshi-bridge/src/rbf/withdraw.rs (L43-46)
```rust
        require!(
            &original_tx_btc_pending_info.account_id == account_id,
            "Not allow"
        );
```
