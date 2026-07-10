### Title
Sub-Minimum BTC Deposits Are Permanently Locked With No User Recovery Path — (File: contracts/satoshi-bridge/src/btc_light_client/deposit.rs)

### Summary
When a user deposits BTC below `min_deposit_amount`, the bridge's `unavailable_utxo_callback` marks the UTXO as verified (blocking the refund system) but mints no nBTC and provides no user-facing recovery path. The BTC is permanently locked from the user's perspective, requiring privileged operator intervention to recover.

### Finding Description
The deposit flow for sub-minimum amounts follows this path:

1. `internal_verify_deposit` checks `deposit_amount < config.min_deposit_amount` and routes to `unavailable_utxo_callback` instead of the normal mint path.

In `unavailable_utxo_callback`:

```rust
require!(
    self.data_mut()
        .verified_deposit_utxo
        .insert(pending_utxo_info.utxo_storage_key.clone()),
    "Already deposit utxo"
);
// ...
self.internal_set_unavailable_utxo(
    &pending_utxo_info.utxo_storage_key,
    pending_utxo_info.utxo,
);
```

The UTXO is inserted into `verified_deposit_utxo` and stored via `internal_set_unavailable_utxo` (a separate storage set from the regular `internal_set_utxo`). No nBTC is minted and no refund is issued.

The refund system (`request_refund`) is the only user-facing recovery mechanism, but it is explicitly blocked for any UTXO already in `verified_deposit_utxo`:

```rust
require!(
    !self
        .data()
        .verified_deposit_utxo
        .contains(&utxo_storage_key),
    "UTXO already verified via deposit"
);
```

Because `unavailable_utxo_callback` inserts the UTXO into `verified_deposit_utxo`, `request_refund_callback` will always panic for sub-minimum deposits. The user cannot call `request_refund` before the relayer calls `verify_deposit` reliably either — the documented race condition shows that if `verify_deposit` wins during the timelock, `execute_refund` is also blocked.

Additionally, `active_utxo_management` (the only other mechanism that could move these UTXOs) is restricted to `Role::DAO` or `Role::Operator` and operates on the regular UTXO set, not the unavailable UTXO set stored by `internal_set_unavailable_utxo`. There is no `claim_lost_found` equivalent for BTC.

### Impact Explanation
A user who accidentally or intentionally sends BTC below `min_deposit_amount` to a bridge deposit address receives no nBTC and has no on-chain path to recover their BTC. The funds are locked in a bridge-controlled MPC address indefinitely. Recovery requires privileged DAO/Operator intervention via `active_utxo_management`, which may not even be possible if unavailable UTXOs are excluded from the regular UTXO set used by that function. This constitutes a stuck bridge state requiring operator intervention, matching the Medium impact class.

**Impact: Medium**

### Likelihood Explanation
Any user can trigger this by sending a BTC amount below `min_deposit_amount` to a deposit address derived from `get_user_deposit_address`. The relayer will then call `verify_deposit` in the normal course of operations, triggering `unavailable_utxo_callback`. This is a realistic accidental scenario (user sends a dust amount, makes a decimal error, or tests with a small amount). No special privileges or coordination are required.

**Likelihood: Medium**

### Recommendation
Add a user-facing refund path for sub-minimum deposits. One approach: instead of inserting the UTXO into `verified_deposit_utxo` in `unavailable_utxo_callback`, store it in a separate `unavailable_utxo_refund_requests` map keyed by UTXO storage key, and add a `refund_unavailable_utxo` function that allows the original depositor (identified via `deposit_msg.recipient_id` or `deposit_msg.refund_address`) to initiate an MPC-signed refund transaction after a timelock. Alternatively, reuse the existing `request_refund` flow by not inserting sub-minimum UTXOs into `verified_deposit_utxo` until a refund is actually executed or the UTXO is spent.

### Proof of Concept

1. User calls `get_user_deposit_address(DepositMsg { recipient_id: "alice", refund_address: None, ... })` and receives a deposit address.
2. User sends 999 satoshis (below `min_deposit_amount`) to that address on Bitcoin.
3. Relayer calls `verify_deposit(deposit_msg, tx_bytes, vout, ...)`.
4. Bridge calls light client → `verify_deposit_callback` → detects `deposit_amount < config.min_deposit_amount` → calls `unavailable_utxo_callback`.
5. `unavailable_utxo_callback` inserts `utxo_storage_key` into `verified_deposit_utxo` and calls `internal_set_unavailable_utxo`. No nBTC minted.
6. User attempts `request_refund(deposit_msg, "bc1q...", tx_bytes, vout, proof, None)`.
7. `request_refund_callback` executes and hits: `require!(!self.data().verified_deposit_utxo.contains(&utxo_storage_key), "UTXO already verified via deposit")` → **panics**.
8. User's 999 satoshis are permanently locked with no on-chain recovery path. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L44-51)
```rust

        if deposit_amount < config.min_deposit_amount {
            promise.then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_UNAVAILABLE_UTXO_CALL_BACK)
                    .unavailable_utxo_callback(recipient_id, pending_utxo_info),
            )
        } else {
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L296-323)
```rust
    pub fn unavailable_utxo_callback(
        &mut self,
        recipient_id: AccountId,
        pending_utxo_info: PendingUTXOInfo,
    ) -> PromiseOrValue<bool> {
        let result_bytes = env::promise_result_checked(0, MAX_BOOL_RESULT)
            .expect("Call verify_transaction_inclusion failed");
        let is_valid = serde_json::from_slice::<bool>(&result_bytes)
            .expect("verify_transaction_inclusion return not bool");
        require!(is_valid, "verify_transaction_inclusion return false");
        require!(
            self.data_mut()
                .verified_deposit_utxo
                .insert(pending_utxo_info.utxo_storage_key.clone()),
            "Already deposit utxo"
        );
        let deposit_amount = u128::from(pending_utxo_info.utxo.balance);
        self.internal_set_unavailable_utxo(
            &pending_utxo_info.utxo_storage_key,
            pending_utxo_info.utxo,
        );
        Event::UnavailableUtxo {
            recipient_id: &recipient_id,
            utxo_storage_key: &pending_utxo_info.utxo_storage_key,
            amount: deposit_amount.into(),
        }
        .emit();
        PromiseOrValue::Value(true)
```

**File:** contracts/satoshi-bridge/src/refund.rs (L253-258)
```rust
        // after a consensus branch change.
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
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
