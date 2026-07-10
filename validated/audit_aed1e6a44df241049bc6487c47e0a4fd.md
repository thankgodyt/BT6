Now I have all the code needed to evaluate the claimed race condition. Let me trace through the exact state transitions.

### Title
Concurrent `request_refund_callback` / `verify_deposit_callback` Race Leaves Refund Request Permanently Stuck — (`contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

An unprivileged user can submit `request_refund` and `verify_deposit` for the same UTXO in the same NEAR block. If `request_refund_callback` executes before `verify_deposit_callback`, both callbacks succeed and the contract reaches an inconsistent state: the UTXO is simultaneously in `refund_requests` (with `executed: false`) and in `verified_deposit_utxo`. Subsequent calls to `execute_refund` are permanently blocked by the guard in `load_refund_request_for_execute`, and no public entrypoint can remove the stuck request — only a DAO/Operator `reject_refund` call can clean it up.

---

### Finding Description

**Entrypoints (both public, unprivileged):**
- `request_refund` → `verify_transaction_inclusion_promise` → `request_refund_callback`
- `verify_deposit` → `verify_transaction_inclusion_promise` → `verify_deposit_callback`

**Exact state-transition trace:**

**Step 1 — `request_refund_callback` executes first.**

The callback checks two guards before inserting the refund request:

```
// refund.rs lines 534–547
require!(!verified_deposit_utxo.contains(&key), "UTXO already verified via deposit");
require!(!refund_requests.contains_key(&key), "Refund request already exists");
refund_requests.insert(key, RefundRequest { executed: false, … });
```

At this moment `verified_deposit_utxo` does not yet contain the key (the deposit callback has not run), so both guards pass. [1](#0-0) 

**Step 2 — `verify_deposit_callback` executes second.**

```
// deposit.rs lines 369–374
require!(
    self.data_mut().verified_deposit_utxo.insert(utxo_storage_key.clone()),
    "Already deposit utxo"
);
// → mints nBTC
```

`verified_deposit_utxo` does not yet contain the key (only `refund_requests` does), so `insert()` returns `true`, the guard passes, and nBTC is minted. [2](#0-1) 

**Post-race state:**
- `refund_requests[key]` exists with `executed = false`
- `verified_deposit_utxo` contains `key`
- nBTC has been minted (correct, one-time)

**Step 3 — `execute_refund` is called after the timelock.**

`load_refund_request_for_execute` evaluates:

```rust
// refund.rs lines 254–258
require!(
    !self.data().verified_deposit_utxo.contains(utxo_storage_key)  // false — key IS present
        || refund_request.executed,                                   // false — executed == false
    "UTXO already verified via deposit, cannot refund"
);
```

`false || false` → the `require!` panics. `execute_refund` can never succeed for this request. [3](#0-2) 

**Step 4 — No public cleanup path exists.**

The only function that removes a refund request without executing it is `internal_reject_refund`, which is gated behind DAO/Operator ACL: [4](#0-3) 

There is no public, unprivileged entrypoint to remove a stuck refund request.

---

### Impact Explanation

- **No unauthorized minting:** nBTC is minted exactly once, correctly, via `verify_deposit_callback`.
- **No double-spend:** `execute_refund` is correctly blocked.
- **Stuck bridge state:** The refund request occupies on-chain storage indefinitely. The user's attached NEAR storage deposit (required by `required_balance_for_request_refund`) is locked until a DAO/Operator calls `reject_refund`. This is a stuck bridge state requiring operator intervention — matching the **Medium** impact category.

---

### Likelihood Explanation

NEAR processes cross-contract receipts asynchronously. Two transactions submitted in the same block can have their callbacks scheduled in either order. The ordering `request_refund_callback` before `verify_deposit_callback` is non-deterministic but reachable without any privileged access. A user who submits both calls (e.g., first depositing, then changing their mind and requesting a refund before the deposit callback lands) can trigger this inadvertently. An attacker can trigger it deliberately.

---

### Recommendation

In `request_refund_callback`, after inserting the refund request, also insert the UTXO key into `verified_deposit_utxo` (or a dedicated "refund-claimed" set) so that a racing `verify_deposit_callback` will fail its `insert()` guard. Alternatively, add a symmetric check in `verify_deposit_callback` that rejects the deposit if a refund request already exists for the UTXO key, and ensure the check and the insert are atomic within the same callback execution (they already are in NEAR's single-threaded execution model — the fix is simply to add the cross-check).

---

### Proof of Concept

```
Block N:
  TX-A: user calls request_refund(utxo=X, …)
        → schedules light_client.verify_transaction_inclusion(X)
  TX-B: user calls verify_deposit(utxo=X, …)
        → schedules light_client.verify_transaction_inclusion(X)

Block N+1 (receipt scheduling, non-deterministic order):
  Receipt-1: request_refund_callback(X)
    verified_deposit_utxo.contains(X) → false  ✓
    refund_requests.contains(X)       → false  ✓
    refund_requests.insert(X, {executed:false})

  Receipt-2: verify_deposit_callback(X)
    verified_deposit_utxo.insert(X)   → true   ✓
    mint nBTC to user

State: refund_requests[X].executed=false, verified_deposit_utxo∋X

Block N+2+timelock:
  user calls execute_refund(X)
    load_refund_request_for_execute:
      !verified_deposit_utxo.contains(X) || executed
      = !true || false = false
      → PANIC: "UTXO already verified via deposit, cannot refund"

Refund request stuck. Only DAO/Operator reject_refund(X) can clear it.
```

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L186-196)
```rust
    /// Reject a pending refund request.
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

**File:** contracts/satoshi-bridge/src/refund.rs (L534-578)
```rust
        // Double-check not finalized (could have been verified between request and callback)
        require!(
            !self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key),
            "UTXO already verified via deposit"
        );

        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );

        let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
        require!(
            resolved_gas_fee < amount,
            "Gas fee must be less than deposit amount"
        );

        Event::RefundRequested {
            deposit_msg: deposit_msg.clone(),
            utxo_storage_key: utxo_storage_key.clone(),
            amount: amount.into(),
            refund_address: refund_address.clone(),
            gas_fee: resolved_gas_fee.into(),
        }
        .emit();

        let refund_request = RefundRequest {
            deposit_msg_json: serde_json::to_string(&deposit_msg).unwrap(),
            utxo_storage_key: utxo_storage_key.clone(),
            tx_bytes,
            vout,
            amount,
            refund_address,
            gas_fee: resolved_gas_fee,
            created_at_sec: nano_to_sec(env::block_timestamp()),
            executed: false,
        };

        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L369-383)
```rust
        require!(
            self.data_mut()
                .verified_deposit_utxo
                .insert(pending_utxo_info.utxo_storage_key.clone()),
            "Already deposit utxo"
        );
        self.internal_mint_promise(
            recipient_id,
            mint_amount,
            protocol_fee,
            relayer_fee,
            pending_utxo_info,
            post_actions,
        )
        .into()
```
