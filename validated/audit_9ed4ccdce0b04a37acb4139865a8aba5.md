### Title
Refund Timelock Reduction Enables Premature Execution of Pending Refund Requests - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary
When the DAO reduces `unsafe_refund_timelock_sec` (or `refund_timelock_sec`) via `update_config`, all existing pending refund requests immediately become executable under the new shorter timelock. The timelock is read from the live config at `execute_refund` time rather than being locked in at `request_refund` time, and no pending requests are cleared when the config changes. This is the direct structural analog to the Oracle quorum-decrement race: a legitimate privileged configuration change retroactively weakens the protection on already-queued pending state, allowing an unprivileged user to race through a window that was supposed to remain closed.

### Finding Description

`resolve_execute_refund_timelock` reads the timelock from the current config at the moment `execute_refund` is called:

```rust
let config = self.internal_config();
if refund_request.deposit_msg().refund_address.is_some() {
    if is_privileged { 0 } else { config.refund_timelock_sec }
} else {
    config.unsafe_refund_timelock_sec   // ← live config, not snapshot
}
```

`load_refund_request_for_execute` then enforces the timelock against the request's `created_at_sec`:

```rust
require!(
    u64::from(now) >= u64::from(refund_request.created_at_sec) + timelock_sec,
    "Refund timelock has not passed yet"
);
```

The `RefundRequest` struct stores only `created_at_sec`; it does not record the timelock that was in effect when the request was submitted. `update_config` applies the new timelock immediately to all existing requests without clearing them:

```rust
pub fn update_config(&mut self, update: ConfigUpdate) {
    assert_one_yocto();
    update.apply(self.internal_mut_config());  // no pending-request flush
}
```

`ConfigUpdate::apply` calls `config.assert_valid()` but performs no cleanup of `refund_requests`.

The `unsafe_refund_timelock_sec` (default 14 days) exists specifically to give DAO/Operator time to review and reject suspicious refund requests where the refund address was supplied by the caller rather than pre-authorized in `deposit_msg`. If the DAO legitimately reduces this value — for example, to improve UX for future requests — every existing pending request with `deposit_msg.refund_address == None` immediately becomes executable under the shorter window, collapsing the review period retroactively.

### Impact Explanation

A user who submitted a refund request with a suspicious or attacker-chosen `refund_address` (and `deposit_msg.refund_address = None`) can monitor the mempool for a DAO `update_config` call that reduces `unsafe_refund_timelock_sec`, then immediately call `execute_refund` in the same block or the next block. The DAO/Operator review window — which may have had days or weeks remaining — is eliminated. The refund PSBT is built and submitted to MPC signing, directing the bridge-held BTC to the attacker-chosen address before the DAO can call `reject_refund`. This is a bypass of the bridge's refund-review policy and constitutes a medium-severity policy bypass with potential for loss of user or protocol funds if the refund address is malicious.

### Likelihood Explanation

The DAO reducing `unsafe_refund_timelock_sec` is a plausible governance action (e.g., reducing from 14 days to 7 days for operational reasons). The DAO may not realize this retroactively affects all in-flight requests. An attacker who has a pending refund request with a malicious address only needs to watch for this governance transaction and race to call `execute_refund` immediately after it lands. No special access is required beyond having previously submitted a `request_refund`.

### Recommendation

Store the resolved timelock inside `RefundRequest` at the time the request is created (in `request_refund_callback`), and use that stored value in `load_refund_request_for_execute` instead of reading from the live config. This mirrors the fix applied in the Oracle report: pending state should carry the policy snapshot under which it was created. Alternatively, when `update_config` reduces either timelock field, flush all pending refund requests that have not yet passed the old timelock.

### Proof of Concept

1. Attacker calls `request_refund` with `deposit_msg.refund_address = None` and `refund_address = <attacker_btc_address>`. The request is stored with `created_at_sec = T` and the current `unsafe_refund_timelock_sec = 1_209_600` (14 days).
2. DAO calls `update_config` with `unsafe_refund_timelock_sec = 86_400` (1 day) for legitimate operational reasons.
3. Attacker observes the DAO transaction in the mempool or on-chain and immediately calls `execute_refund(utxo_storage_key, None)`.
4. `resolve_execute_refund_timelock` returns `config.unsafe_refund_timelock_sec = 86_400`.
5. `load_refund_request_for_execute` checks `now >= T + 86_400`. If at least 1 day has elapsed since the request was submitted (easily satisfied), the check passes.
6. `finalize_refund_with_psbt` is called, creating a `BTCPendingInfo` that routes the bridge-held BTC to the attacker's address via MPC signing — before the DAO can call `reject_refund`.

Relevant code locations: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** contracts/satoshi-bridge/src/api/management.rs (L281-284)
```rust
    pub fn update_config(&mut self, update: ConfigUpdate) {
        assert_one_yocto();
        update.apply(self.internal_mut_config());
    }
```

**File:** contracts/satoshi-bridge/src/config.rs (L266-301)
```rust
    pub fn apply(self, config: &mut Config) {
        macro_rules! set_if_some {
            ($field:ident) => {
                if let Some(v) = self.$field {
                    config.$field = v;
                }
            };
        }
        set_if_some!(btc_light_client_account_id);
        set_if_some!(nbtc_account_id);
        set_if_some!(confirmations_delta);
        set_if_some!(extra_msg_confirmations_delta);
        set_if_some!(deposit_bridge_fee);
        set_if_some!(withdraw_bridge_fee);
        set_if_some!(min_deposit_amount);
        set_if_some!(min_withdraw_amount);
        set_if_some!(min_change_amount);
        set_if_some!(max_change_amount);
        set_if_some!(min_btc_gas_fee);
        set_if_some!(max_btc_gas_fee);
        set_if_some!(max_withdrawal_input_number);
        set_if_some!(max_change_number);
        set_if_some!(max_active_utxo_management_input_number);
        set_if_some!(max_active_utxo_management_output_number);
        set_if_some!(active_management_lower_limit);
        set_if_some!(active_management_upper_limit);
        set_if_some!(passive_management_lower_limit);
        set_if_some!(passive_management_upper_limit);
        set_if_some!(rbf_num_limit);
        set_if_some!(max_btc_tx_pending_sec);
        set_if_some!(unhealthy_utxo_amount);
        set_if_some!(refund_timelock_sec);
        set_if_some!(unsafe_refund_timelock_sec);

        config.assert_valid();
    }
```
