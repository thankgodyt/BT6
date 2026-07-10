### Title
Unpermissioned `execute_refund` Allows Any Caller to Hijack Refund `BTCPendingInfo`, Permanently Blocking Re-execution and New Refund Requests - (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`execute_refund` carries no access control. Any NEAR account can call it for any pending refund request. The caller's account ID is recorded as the owner of the resulting `BTCPendingInfo`. Because the refund PSBT is fully deterministic (fixed inputs and outputs), a second call to `execute_refund` by the legitimate user panics with `"pending info already exist"`. Simultaneously, the UTXO is permanently inserted into `verified_deposit_utxo`, blocking any future `request_refund` for the same UTXO. The user is forced outside the normal refund flow to recover their BTC.

---

### Finding Description

`execute_refund` in `contracts/satoshi-bridge/src/api/bridge.rs` is decorated only with `#[payable]` and `#[pause(except(roles(Role::DAO)))]` — no caller restriction: [1](#0-0) 

Inside `internal_execute_refund` (Bitcoin path), the caller is captured unconditionally: [2](#0-1) 

`finalize_refund_with_psbt` then stores the caller as `account_id` of the new `BTCPendingInfo`: [3](#0-2) 

It also inserts the UTXO into `verified_deposit_utxo` to block a later `verify_deposit`: [4](#0-3) 

And it panics if a `BTCPendingInfo` with the same deterministic `btc_pending_id` already exists: [5](#0-4) 

The `btc_pending_id` is derived from the PSBT via `psbt.get_pending_id()`. Because the PSBT is built from fixed data (the deposit UTXO outpoint, the stored `refund_address`, and the stored `gas_fee`), it is fully deterministic — any two calls to `execute_refund` for the same `utxo_storage_key` produce the same `btc_pending_id`.

**Attack sequence:**

1. Alice calls `request_refund` for her stuck BTC deposit. A `RefundRequest` is stored.
2. The timelock elapses.
3. Attacker calls `execute_refund(utxo_storage_key)` before Alice:
   - `BTCPendingInfo` is created with `account_id = attacker`.
   - UTXO is inserted into `verified_deposit_utxo`.
   - `refund_request.executed = true` is stored.
4. Alice calls `execute_refund` — `load_refund_request_for_execute` passes (because `executed == true` is explicitly allowed for re-execution), but `finalize_refund_with_psbt` panics: `"pending info already exist"`. [6](#0-5) 

5. Alice tries `request_refund` for the same UTXO — blocked by: [7](#0-6) 

6. The attacker simply never calls `sign_btc_transaction`, leaving the `BTCPendingInfo` in `PendingSign` state indefinitely.

**Recovery path (partial):** `sign_btc_transaction` itself has no caller check: [8](#0-7) 

Alice can discover the `btc_pending_id` from on-chain events and call `sign_btc_transaction` herself. The callback uses `btc_pending_info.account_id` (the attacker) for bookkeeping, which succeeds because the attacker's account has the ID in `btc_pending_sign_ids`. The BTC eventually reaches the correct `refund_address`. However, this requires Alice to take non-obvious out-of-band steps, and if the attacker's account has exhausted `pending_sign_capacity`, even this path is blocked.

The Zcash path (`zcash_utils/refund.rs`) has the same root cause — `caller` is captured from `env::predecessor_account_id()` and forwarded into `finalize_refund_with_psbt`: [9](#0-8) 

---

### Impact Explanation

An attacker can front-run any user's `execute_refund` call, permanently blocking:
- Re-execution of the refund via `execute_refund` (`"pending info already exist"` panic).
- Creation of a new refund request via `request_refund` (UTXO permanently in `verified_deposit_utxo`).

The user's BTC is stuck in the bridge-controlled deposit address until they discover and manually invoke `sign_btc_transaction` on the attacker-owned `BTCPendingInfo`. If the attacker's account has hit `pending_sign_capacity`, even this recovery is blocked, making the lock permanent without DAO intervention.

This matches: **Medium — attacker-triggered temporary (potentially permanent) locking of bridged funds; broken callback/state requiring operator intervention.**

---

### Likelihood Explanation

High. After the timelock elapses, `execute_refund` is callable by any NEAR account with only a small storage deposit attached. No special knowledge, tokens, or privileges are required. The attacker only needs to observe the `RefundRequested` event (which emits `utxo_storage_key`) and call `execute_refund` before the legitimate user. [10](#0-9) 

---

### Recommendation

Restrict `execute_refund` to the original depositor. The `RefundRequest` already stores `deposit_msg_json`, from which the `recipient_id` (the intended beneficiary) can be recovered. Add a caller check at the top of `execute_refund`:

```rust
pub fn execute_refund(
    &mut self,
    utxo_storage_key: String,
    chain_specific_data: Option<ChainSpecificData>,
) -> PromiseOrValue<()> {
    let caller = env::predecessor_account_id();
    let refund_request: RefundRequest = self
        .data()
        .refund_requests
        .get(&utxo_storage_key)
        .expect("Refund request not found")
        .into();
    let deposit_msg = refund_request.deposit_msg();
    let is_privileged = self.acl_has_any_role(
        vec![Role::DAO.into(), Role::RefundOperator.into(), Role::Operator.into()],
        caller.clone(),
    );
    require!(
        is_privileged || caller == deposit_msg.recipient_id,
        "Only the deposit owner or a privileged role can execute a refund"
    );
    let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
    self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
}
```

This mirrors the fix applied in the referenced Maia DAO report: restrict the retry/recovery function to the original owner, preventing any third party from hijacking the pending state.

---

### Proof of Concept

```
1. Alice calls request_refund(deposit_msg, refund_address, tx_bytes, vout, proof)
   → RefundRequest stored at utxo_storage_key

2. Timelock elapses (refund_timelock_sec passes)

3. Attacker calls execute_refund(utxo_storage_key)
   → BTCPendingInfo created with account_id = attacker
   → verified_deposit_utxo.insert(utxo_storage_key)
   → refund_request.executed = true

4. Alice calls execute_refund(utxo_storage_key)
   → load_refund_request_for_execute passes (executed==true is allowed)
   → finalize_refund_with_psbt panics: "pending info already exist"
   ✗ Alice cannot re-execute

5. Alice calls request_refund(same UTXO)
   → request_refund_callback panics: "UTXO already verified via deposit"
   ✗ Alice cannot create a new refund request

6. Attacker never calls sign_btc_transaction
   → BTCPendingInfo stuck in PendingSign indefinitely
   → Alice's BTC locked in deposit address
```

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

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L35-42)
```rust
        let caller = env::predecessor_account_id();
        self.finalize_refund_with_psbt(
            caller,
            refund_request,
            psbt,
            refund_amount,
            utxo_storage_key,
        );
```

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

**File:** contracts/satoshi-bridge/src/refund.rs (L344-346)
```rust
        let btc_pending_info = BTCPendingInfo {
            account_id: caller.clone(),
            btc_pending_id: btc_pending_id.clone(),
```

**File:** contracts/satoshi-bridge/src/refund.rs (L366-372)
```rust
        require!(
            self.data_mut()
                .btc_pending_infos
                .insert(btc_pending_id.clone(), btc_pending_info.into())
                .is_none(),
            "pending info already exist"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L377-380)
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

**File:** contracts/satoshi-bridge/src/refund.rs (L555-562)
```rust
        Event::RefundRequested {
            deposit_msg: deposit_msg.clone(),
            utxo_storage_key: utxo_storage_key.clone(),
            amount: amount.into(),
            refund_address: refund_address.clone(),
            gas_fee: resolved_gas_fee.into(),
        }
        .emit();
```

**File:** contracts/satoshi-bridge/src/api/chain_signatures.rs (L21-43)
```rust
    pub fn sign_btc_transaction(
        &mut self,
        btc_pending_sign_id: String,
        sign_index: usize,
        key_version: u32,
    ) -> PromiseOrValue<bool> {
        let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);
        btc_pending_info.assert_pending_sign();
        if let Some(original_tx_id) = btc_pending_info.get_original_tx_id() {
            if !self.check_btc_pending_info_exists(original_tx_id) {
                require!(
                    self.internal_unwrap_mut_account(&btc_pending_info.account_id.clone())
                        .btc_pending_sign_ids
                        .remove(&btc_pending_sign_id),
                    "Internal error"
                );
                self.internal_remove_btc_pending_info(&btc_pending_sign_id);
                return PromiseOrValue::Value(true);
            }
        }
        self.internal_sign_btc_transaction(btc_pending_sign_id, sign_index, key_version)
            .into()
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/refund.rs (L34-46)
```rust
        let caller = env::predecessor_account_id();
        PromiseOrValue::Promise(
            self.get_last_block_height_promise().then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_EXECUTE_REFUND_CALLBACK)
                    .execute_refund_callback(
                        utxo_storage_key,
                        caller,
                        timelock_sec,
                        chain_specific_data,
                    ),
            ),
        )
```
