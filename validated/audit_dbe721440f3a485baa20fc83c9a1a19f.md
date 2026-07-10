### Title
Refund Timelock Not Snapshotted Per Request, Allowing Retroactive Changes to Affect Pending Refunds - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary
The `RefundRequest` struct records `created_at_sec` but never captures the timelock value in effect at request time. When `execute_refund` is called, `resolve_execute_refund_timelock` reads `refund_timelock_sec` / `unsafe_refund_timelock_sec` from the live config. A DAO update to either field retroactively changes the unlock time for every pending refund request, mirroring the M-04 pattern exactly.

### Finding Description
`RefundRequest` stores the timestamp of creation but no timelock snapshot:

```rust
pub struct RefundRequest {
    // ...
    pub created_at_sec: u32,
    pub executed: bool,
    // ← no timelock_sec field
}
```

At execution time, `resolve_execute_refund_timelock` fetches the timelock from the current global config:

```rust
pub(crate) fn resolve_execute_refund_timelock(&self, utxo_storage_key: &str) -> u64 {
    // ...
    let config = self.internal_config();
    if refund_request.deposit_msg().refund_address.is_some() {
        if is_privileged { 0 } else { config.refund_timelock_sec }
    } else {
        config.unsafe_refund_timelock_sec
    }
}
```

That returned value is then compared against the stored `created_at_sec` in `load_refund_request_for_execute`:

```rust
require!(
    u64::from(now) >= u64::from(refund_request.created_at_sec) + timelock_sec,
    "Refund timelock has not passed yet"
);
```

`ConfigUpdate` exposes both fields as mutable and the DAO can call `update_config` at any time:

```rust
pub refund_timelock_sec: Option<u64>,
pub unsafe_refund_timelock_sec: Option<u64>,
```

Because the timelock is resolved from the live config rather than from a per-request snapshot, any config update retroactively shifts the unlock time for all pending refund requests.

### Impact Explanation
**Medium.** Two directions of harm exist:

1. **Timelock increase** – A DAO update that raises `refund_timelock_sec` or `unsafe_refund_timelock_sec` after users have submitted refund requests forces those users to wait longer than the protocol promised at request time. Their deposited BTC/ZEC remains locked in the bridge's UTXO pool for an extended, unexpected period — a temporary locking of bridged funds.

2. **Timelock decrease** – A reduction allows `execute_refund` to be called before the originally intended delay has elapsed, bypassing the bridge's anti-fraud window that gives the DAO/Operator time to reject suspicious requests (the explicit purpose of `unsafe_refund_timelock_sec`).

### Likelihood Explanation
**Medium.** The DAO legitimately adjusts config parameters over the protocol's lifetime. Any such adjustment — even a well-intentioned one — silently and immediately changes the effective unlock time for every pending refund. No malicious intent is required; a routine governance action is sufficient to trigger the inconsistency.

### Recommendation
Snapshot the applicable timelock into `RefundRequest` at the moment the request is stored in `request_refund_callback`, and use that stored value in `resolve_execute_refund_timelock` instead of reading from the live config:

```rust
pub struct RefundRequest {
    // existing fields ...
    pub created_at_sec: u32,
    pub timelock_sec: u64,   // ← add this
    pub executed: bool,
}
```

In `request_refund_callback`, resolve and store the timelock:

```rust
let config = self.internal_config();
let timelock_sec = if deposit_msg.refund_address.is_some() {
    config.refund_timelock_sec
} else {
    config.unsafe_refund_timelock_sec
};
let refund_request = RefundRequest {
    // ...
    timelock_sec,
    // ...
};
```

In `resolve_execute_refund_timelock`, return `refund_request.timelock_sec` (with the existing privilege fast-path returning `0` unchanged).

### Proof of Concept

1. User calls `request_refund` when `unsafe_refund_timelock_sec = 14 days`. The request is stored with `created_at_sec = T`.
2. DAO calls `update_config` setting `unsafe_refund_timelock_sec = 30 days`.
3. After 14 days the user calls `execute_refund`. `resolve_execute_refund_timelock` reads the current config and returns `30 days`. The check `now >= T + 30 days` fails, and the user's refund is blocked for an additional 16 days beyond what was promised.

Conversely, if the DAO decreases `unsafe_refund_timelock_sec` from 14 days to 1 day, `execute_refund` succeeds after only 1 day, eliminating the fraud-review window for all requests that were submitted under the 14-day policy.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L32-47)
```rust
pub struct RefundRequest {
    pub deposit_msg_json: String,
    pub utxo_storage_key: String,
    pub tx_bytes: Base64VecU8,
    pub vout: usize,
    pub amount: u128,
    pub refund_address: String,
    pub gas_fee: u128,
    pub created_at_sec: u32,
    /// Set once `execute_refund` has built a refund transaction for this request.
    /// While `true` the request is kept (not removed) so `execute_refund` can be
    /// called again to re-create the transaction (e.g. after a consensus branch
    /// change); it is removed only when the refund is finalized in
    /// `verify_refund_finalize`.
    pub executed: bool,
}
```

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

**File:** contracts/satoshi-bridge/src/config.rs (L114-118)
```rust
    // Timelock for refunds where `deposit_msg.refund_address` is pre-authorized.
    pub refund_timelock_sec: u64,
    // Timelock for refunds where the refund address comes from the request caller
    // (`deposit_msg.refund_address` was None). Must be >= `refund_timelock_sec`.
    pub unsafe_refund_timelock_sec: u64,
```

**File:** contracts/satoshi-bridge/src/config.rs (L261-262)
```rust
    pub refund_timelock_sec: Option<u64>,
    pub unsafe_refund_timelock_sec: Option<u64>,
```
