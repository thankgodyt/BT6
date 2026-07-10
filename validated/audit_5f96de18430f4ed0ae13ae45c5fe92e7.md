### Title
`DAO`/`RefundOperator` Privilege Check Incorrectly Nested Inside Pre-Authorized Address Branch, Blocking Fast-Track of Unsafe Refunds — (File: `contracts/satoshi-bridge/src/refund.rs`)

### Summary
`resolve_execute_refund_timelock` in `refund.rs` nests the `is_privileged` check inside the `refund_address.is_some()` branch. Privileged callers (`Role::DAO` or `Role::RefundOperator`) receive a zero timelock only when the deposit message already contains a pre-authorized refund address. When the refund address was supplied by the caller of `request_refund` (`deposit_msg.refund_address` is `None`), the function unconditionally returns `config.unsafe_refund_timelock_sec` — even for privileged callers. This is the same boolean-logic class as the ZeroLendToken report: a guard intended to exempt a privileged actor from a restriction fails to do so because the exemption check is nested inside the wrong branch.

### Finding Description
In `resolve_execute_refund_timelock` (`contracts/satoshi-bridge/src/refund.rs` lines 216–228):

```rust
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
``` [1](#0-0) 

The outer branch checks whether the deposit message contains a pre-authorized refund address. Only inside the `true` arm is `is_privileged` consulted. In the `false` arm (caller-supplied address), `is_privileged` is never evaluated and `unsafe_refund_timelock_sec` is returned unconditionally.

The comment in the `else` arm reads: *"to give DAO/Operator time to reject suspicious requests."* This confirms the design intent: the longer timelock exists so the DAO/Operator can call `internal_reject_refund` before an attacker executes a suspicious refund. [2](#0-1) 

But if the DAO/Operator is the one calling `execute_refund`, they have already decided to approve the request — the timelock serves no protective purpose for them. The `is_privileged` variable is computed correctly (checking `Role::DAO` and `Role::RefundOperator`) but is simply never reached in the caller-supplied-address branch. [3](#0-2) 

The downstream enforcement in `load_refund_request_for_execute` then enforces the returned timelock unconditionally:

```rust
require!(
    u64::from(now) >= u64::from(refund_request.created_at_sec) + timelock_sec,
    "Refund timelock has not passed yet"
);
``` [4](#0-3) 

### Impact Explanation
A `DAO` or `RefundOperator` account that wishes to immediately execute a refund whose address was supplied by the caller of `request_refund` is forced to wait the full `unsafe_refund_timelock_sec` before the call succeeds. During this window the user's deposited BTC/ZEC remains locked in the bridge and cannot be returned. This is a stuck-state / temporary locking of bridged funds reachable through the normal public refund path, without direct theft.

### Likelihood Explanation
Any user who calls `request_refund` without a pre-authorized refund address embedded in their `DepositMsg` (i.e., `deposit_msg.refund_address` is `None`) triggers this code path. This is the common case for users who did not embed a refund address at deposit time. The DAO or RefundOperator may legitimately need to fast-track such refunds (e.g., to recover funds for a known user quickly after a failed deposit), but the bug prevents it. The scenario is realistic and reachable without any privileged setup beyond normal bridge operation.

### Recommendation
Hoist the `is_privileged` check to the outermost level so privileged callers always receive a zero timelock regardless of whether the refund address was pre-authorized:

```rust
if is_privileged {
    0
} else if refund_request.deposit_msg().refund_address.is_some() {
    config.refund_timelock_sec
} else {
    config.unsafe_refund_timelock_sec
}
```

### Proof of Concept
1. Deploy the bridge contract with a non-zero `unsafe_refund_timelock_sec` (e.g., 86 400 seconds).
2. Grant `Role::RefundOperator` to account `refund_op`.
3. A user makes a BTC deposit without a pre-authorized refund address in their `DepositMsg`.
4. The user calls `request_refund` with a caller-supplied `refund_address`. The stored `RefundRequest` has `deposit_msg.refund_address == None`.
5. `refund_op` immediately calls `execute_refund` for this request.
6. `resolve_execute_refund_timelock` is invoked. `is_privileged` is `true`, but the outer branch evaluates `refund_request.deposit_msg().refund_address.is_some()` as `false`, so the function returns `config.unsafe_refund_timelock_sec` without ever consulting `is_privileged`.
7. `load_refund_request_for_execute` checks `now >= created_at_sec + unsafe_refund_timelock_sec`, which fails immediately after the request is created.
8. The call reverts with `"Refund timelock has not passed yet"` even though `refund_op` is a privileged actor — the user's funds remain locked.
9. Apply the recommended fix (hoist `is_privileged` check) and repeat: `refund_op` can now execute the refund immediately with a zero timelock.

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

**File:** contracts/satoshi-bridge/src/refund.rs (L244-248)
```rust
        let now = nano_to_sec(env::block_timestamp());
        require!(
            u64::from(now) >= u64::from(refund_request.created_at_sec) + timelock_sec,
            "Refund timelock has not passed yet"
        );
```
