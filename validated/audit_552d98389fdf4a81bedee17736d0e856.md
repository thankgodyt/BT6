### Title
`require_pending_sign_capacity` Unconditionally Blocks Refund Re-Execution, Permanently Locking User BTC Until Operator Intervention - (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`finalize_refund_with_psbt` unconditionally enforces `require_pending_sign_capacity` before creating a refund pending-sign entry. The code explicitly preserves the refund request after a first `execute_refund` call so the function can be called again (e.g., after a consensus branch change), but the capacity check makes that re-execution impossible whenever the first attempt left a `Refund(PendingSign)` entry in place. There is no user-accessible path to remove that stuck entry while the refund request is still active, leaving the user's deposited BTC inaccessible without DAO/Operator intervention.

---

### Finding Description

**Root cause — unconditional capacity check in `finalize_refund_with_psbt`:**

```rust
// refund.rs lines 339-342
if !self.check_account_exists(&caller) {
    self.internal_set_account(&caller, crate::Account::new(&caller));
}
self.require_pending_sign_capacity(&caller);   // ← always enforced
``` [1](#0-0) 

`require_pending_sign_capacity` panics when the account's `pending_sign_count()` is not strictly less than `get_max_pending_sign_txs`, which defaults to **1** for every account that has no explicit entry in `pending_tx_limits`. [2](#0-1) 

**Design intent contradicts the check — re-execution is explicitly planned:**

After a successful `execute_refund`, the code deliberately keeps the refund request alive and marks it `executed = true` so the function can be called again:

```rust
// refund.rs lines 395-401
// Keep the request (so `execute_refund` can be called again to re-create
// the transaction) but mark it executed; it is removed only when the
// refund is finalized in `verify_refund_finalize`.
refund_request.executed = true;
self.data_mut()
    .refund_requests
    .insert(utxo_storage_key, refund_request.into());
``` [3](#0-2) 

But the first `execute_refund` call inserts a `Refund(PendingSign)` entry into `btc_pending_infos` and into the account's `btc_pending_sign_ids`. Any subsequent call to `execute_refund` hits `require_pending_sign_capacity` and panics with "Too many pending sign transactions" before it can reach `finalize_refund_with_psbt`.

**No user-accessible escape hatch:**

`remove_refund_pending_tx_id` — the only function that can delete a stuck refund pending-sign entry — explicitly blocks removal while the refund request is still active:

```rust
// refund.rs lines 419-424
require!(
    !self
        .data()
        .refund_requests
        .contains_key(&utxo_storage_keys[0]),
    "refund request still active"
);
``` [4](#0-3) 

The public entry point for this function is gated behind `#[trusted_relayer]` and `#[pause]`, but even a trusted relayer cannot call it while the request exists. [5](#0-4) 

There is also no `cancel_refund` equivalent — `cancel_withdraw` only handles `WithdrawOriginal` state and is restricted to `Role::DAO` / `Role::Operator` anyway. [6](#0-5) 

---

### Impact Explanation

A user whose deposited BTC was never finalized via `verify_deposit` can submit a `request_refund` and, after the timelock, call `execute_refund`. If the MPC signing step for that refund fails or stalls (the pending-sign entry is created before the MPC call returns), the user is left with:

- A live `RefundRequest` (so `remove_refund_pending_tx_id` is blocked).
- A `Refund(PendingSign)` entry consuming their entire pending-sign capacity (default = 1).
- No ability to call `execute_refund` again.
- No user-accessible function to clear the stuck entry.

The user's BTC remains locked in the bridge's MPC-controlled deposit address indefinitely. Resolution requires the DAO to (1) reject the refund request, (2) call `remove_refund_pending_tx_id`, and (3) have the user re-submit `request_refund` and wait through the full timelock again. This matches **Medium — stuck bridge state requiring operator intervention**.

The same blockage occurs if the user has a separate withdrawal stuck in `PendingSign` (e.g., MPC network outage) at the time they try to execute a refund for an unrelated deposit.

---

### Likelihood Explanation

MPC signing is an asynchronous cross-contract call. Any transient failure in the chain-signatures contract, a gas exhaustion in the signing callback, or a consensus branch change (explicitly called out in the code comments as a reason to re-run `execute_refund`) leaves the pending-sign entry in place. This is not a theoretical edge case — the developers themselves documented the re-execution use case. The default pending-sign limit of 1 means a single such event is sufficient to trigger the lock.

---

### Recommendation

Move `require_pending_sign_capacity` inside a guard that skips it when the refund request is already marked `executed` (i.e., this is a re-execution attempt), or exempt refund-type pending entries from the capacity count entirely. For example:

```rust
// Only enforce capacity on the *first* execution attempt
if !refund_request.executed {
    self.require_pending_sign_capacity(&caller);
}
```

Alternatively, introduce a dedicated `cancel_refund_pending_sign` function (analogous to `cancel_withdraw`) that DAO/Operator or the user themselves can call to clear a stuck refund pending-sign entry without first having to destroy the refund request.

---

### Proof of Concept

1. User deposits BTC to the bridge deposit address; the relayer never calls `verify_deposit`.
2. User calls `request_refund` with a valid proof — succeeds; a `RefundRequest` is stored.
3. Timelock elapses; user calls `execute_refund`.
   - `finalize_refund_with_psbt` runs, passes `require_pending_sign_capacity` (count = 0 < 1), inserts `Refund(PendingSign)` into `btc_pending_infos`, and marks `refund_request.executed = true`.
   - MPC signing is requested but the callback fails (network issue / gas exhaustion).
   - The `Refund(PendingSign)` entry remains; `btc_pending_sign_ids.len() == 1`.
4. User calls `execute_refund` again (as the code design intends).
   - `finalize_refund_with_psbt` is reached; `require_pending_sign_capacity` fires: `1 < 1` is false → **panic "Too many pending sign transactions"**.
5. User calls `remove_refund_pending_tx_id(tx_id)`.
   - `internal_remove_refund_pending_tx_id` checks `!refund_requests.contains_key(...)` → **panic "refund request still active"**.
6. User's BTC is locked. No further user action is possible; DAO intervention is required.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L339-342)
```rust
        if !self.check_account_exists(&caller) {
            self.internal_set_account(&caller, crate::Account::new(&caller));
        }
        self.require_pending_sign_capacity(&caller);
```

**File:** contracts/satoshi-bridge/src/refund.rs (L395-401)
```rust
        // Keep the request (so `execute_refund` can be called again to re-create
        // the transaction) but mark it executed; it is removed only when the
        // refund is finalized in `verify_refund_finalize`.
        refund_request.executed = true;
        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());
```

**File:** contracts/satoshi-bridge/src/refund.rs (L419-424)
```rust
            !self
                .data()
                .refund_requests
                .contains_key(&utxo_storage_keys[0]),
            "refund request still active"
        );
```

**File:** contracts/satoshi-bridge/src/account.rs (L105-123)
```rust
    pub fn get_max_pending_sign_txs(&self, account_id: &AccountId) -> u32 {
        self.data()
            .pending_tx_limits
            .get(account_id)
            .copied()
            .unwrap_or(1)
    }

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L283-299)
```rust
    #[access_control_any(roles(Role::DAO, Role::Operator))]
    #[pause(except(roles(Role::DAO)))]
    pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
        assert_one_yocto();
        let user_account_id = self
            .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
            .account_id
            .clone();
        self.require_pending_sign_capacity(&user_account_id);

        self.cancel_withdraw_chain_specific(
            user_account_id,
            original_btc_pending_verify_id,
            output,
            None,
        );
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
