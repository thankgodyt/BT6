### Title
Mutable `refund_timelock_sec`/`unsafe_refund_timelock_sec` Retroactively Affects All Pending Refund Requests — (`contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`resolve_execute_refund_timelock()` reads `refund_timelock_sec` and `unsafe_refund_timelock_sec` from the **current** config at execution time, not from the value in effect when the refund request was created. Because `update_config` can change these values at any time, a DAO update retroactively shortens or extends the timelock for every existing pending refund request — directly analogous to the `fundingDuration` "time travel" bug in the reference report.

---

### Finding Description

`RefundRequest` stores `created_at_sec` at submission time: [1](#0-0) 

But `resolve_execute_refund_timelock()` fetches the timelock from the **live** config: [2](#0-1) 

That value is then used in `load_refund_request_for_execute()` against the stored `created_at_sec`: [3](#0-2) 

`refund_timelock_sec` and `unsafe_refund_timelock_sec` are both mutable fields in `Config`: [4](#0-3) 

They are updated without any guard on existing pending requests via `update_config` → `ConfigUpdate::apply`: [5](#0-4) 

The DAO calls `update_config` through: [6](#0-5) 

The `unsafe_refund_timelock_sec` path is the most security-critical. Its purpose is explicitly to give the DAO time to reject suspicious refund requests where the caller supplied their own `refund_address` (i.e., `deposit_msg.refund_address` was `None`): [7](#0-6) 

---

### Impact Explanation

**Decreasing the timelock (most dangerous):** If the DAO reduces `unsafe_refund_timelock_sec` from 14 days to, say, 2 days for operational reasons, every existing pending refund request that is older than 2 days immediately becomes executable — including suspicious ones that were submitted specifically to exploit this window. The attacker can call `execute_refund` before the DAO realizes the retroactive effect, bypassing the security review window entirely and redirecting bridge-controlled BTC/ZEC to an attacker-controlled address.

**Increasing the timelock:** Existing refund requests that were already past their timelock and eligible for execution are retroactively blocked. Legitimate users who submitted refunds and waited the full original period are now stuck, requiring operator intervention to resolve — a stuck bridge state.

Both directions match the allowed impact scope: bypass of bridge policy and attacker-triggered temporary (or permanent) locking of bridged funds.

---

### Likelihood Explanation

The DAO is expected to tune operational parameters over the bridge's lifetime. Reducing `unsafe_refund_timelock_sec` is a plausible legitimate action (e.g., to improve UX after the protocol matures). The DAO may not audit every pending refund request before making such a change, especially if many requests are in flight. An attacker who has already submitted a suspicious refund request only needs to wait for any DAO config update that shortens the timelock, then immediately call `execute_refund`. This is analogous to the reference report's scenario where a user cannot know if `fundingDuration` was changed before their transaction executes.

---

### Recommendation

Snapshot the applicable timelock at request creation time and store it inside `RefundRequest`. Replace the live-config lookup in `resolve_execute_refund_timelock` with the stored value:

```rust
pub struct RefundRequest {
    // ... existing fields ...
    pub timelock_sec: u64,   // snapshotted at request_refund_callback time
}
```

In `request_refund_callback`, set `timelock_sec` from the config at that moment:

```rust
let timelock_sec = if deposit_msg.refund_address.is_some() {
    config.refund_timelock_sec
} else {
    config.unsafe_refund_timelock_sec
};
// store in RefundRequest
```

Then `load_refund_request_for_execute` uses `refund_request.timelock_sec` directly, making the timelock immutable for each individual request after creation. This mirrors the reference report's Option 2 mitigation: store the epoch boundary at creation and advance it by the duration, rather than recomputing from a mutable global.

---

### Proof of Concept

1. Attacker submits a refund request with a self-supplied `refund_address` (no pre-authorized address in `deposit_msg`). `unsafe_refund_timelock_sec` = 14 days applies. `created_at_sec` = T.
2. At T + 3 days, the DAO calls `update_config` with `unsafe_refund_timelock_sec = 2 days` for legitimate operational reasons.
3. At T + 3 days (immediately after the config update), the attacker calls `execute_refund`. The check evaluates: `now (T+3d) >= created_at_sec (T) + timelock_sec (2d)` → `3d >= 2d` → **passes**.
4. The refund is executed, sending BTC/ZEC to the attacker's address, 11 days before the originally intended review window would have closed.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L201-228)
```rust
    pub(crate) fn resolve_execute_refund_timelock(&self, utxo_storage_key: &str) -> u64 {
        require!(
            env::attached_deposit() >= self.required_balance_for_execute_refund(),
            "Insufficient deposit for storage"
        );
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

**File:** contracts/satoshi-bridge/src/refund.rs (L244-248)
```rust
        let now = nano_to_sec(env::block_timestamp());
        require!(
            u64::from(now) >= u64::from(refund_request.created_at_sec) + timelock_sec,
            "Refund timelock has not passed yet"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L564-574)
```rust
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
```

**File:** contracts/satoshi-bridge/src/config.rs (L114-118)
```rust
    // Timelock for refunds where `deposit_msg.refund_address` is pre-authorized.
    pub refund_timelock_sec: u64,
    // Timelock for refunds where the refund address comes from the request caller
    // (`deposit_msg.refund_address` was None). Must be >= `refund_timelock_sec`.
    pub unsafe_refund_timelock_sec: u64,
```

**File:** contracts/satoshi-bridge/src/config.rs (L296-299)
```rust
        set_if_some!(unhealthy_utxo_amount);
        set_if_some!(refund_timelock_sec);
        set_if_some!(unsafe_refund_timelock_sec);

```

**File:** contracts/satoshi-bridge/src/api/management.rs (L280-284)
```rust
    #[access_control_any(roles(Role::DAO))]
    pub fn update_config(&mut self, update: ConfigUpdate) {
        assert_one_yocto();
        update.apply(self.internal_mut_config());
    }
```
