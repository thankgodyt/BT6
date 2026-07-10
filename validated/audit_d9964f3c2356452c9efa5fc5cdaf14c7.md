### Title
Permissionless `execute_refund` Allows Any Caller to Hijack Refund Signing, Locking User's BTC Refund - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary
`execute_refund` is callable by any NEAR account after the timelock. It creates a `BTCPendingInfo` keyed to the **caller's** `account_id`. An attacker who calls it first takes ownership of the signing slot. The legitimate user cannot sign (the pending-sign ID is registered under the attacker's account) and, on Bitcoin, cannot re-execute (the deterministic PSBT produces the same `btc_pending_id`, which is rejected as a duplicate). The user's BTC refund is stuck until DAO/Operator intervention.

### Finding Description

`execute_refund` carries no caller restriction beyond the timelock:

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
``` [1](#0-0) 

`resolve_execute_refund_timelock` only adjusts the timelock duration for privileged callers; it does not restrict who may call the function. [2](#0-1) 

Inside `finalize_refund_with_psbt`, the `BTCPendingInfo` is stamped with the **caller's** `account_id`, and the pending-sign ID is inserted into the **caller's** account:

```rust
let btc_pending_info = BTCPendingInfo {
    account_id: caller.clone(),
    ...
};
...
self.internal_unwrap_mut_account(&caller)
    .btc_pending_sign_ids
    .insert(btc_pending_id.clone());
``` [3](#0-2) 

The `RefundRequest` does **not** record the original requester's `account_id`, so there is no stored identity to enforce caller restriction:

```rust
let refund_request = RefundRequest {
    deposit_msg_json: ...,
    utxo_storage_key: ...,
    tx_bytes,
    vout,
    amount,
    refund_address,
    gas_fee: resolved_gas_fee,
    created_at_sec: nano_to_sec(env::block_timestamp()),
    executed: false,
};
``` [4](#0-3) 

On Bitcoin, the PSBT is deterministic (same inputs/outputs → same txid). A second call to `execute_refund` by the legitimate user is rejected:

```rust
require!(
    self.data_mut()
        .btc_pending_infos
        .insert(btc_pending_id.clone(), btc_pending_info.into())
        .is_none(),
    "pending info already exist"
);
``` [5](#0-4) 

This is confirmed by the integration test `test_refund_execute_twice_different_account`, which shows that a second caller is rejected with "pending info already exist" after the first caller has already executed: [6](#0-5) 

### Impact Explanation

An attacker who calls `execute_refund` first (after the timelock) takes ownership of the `BTCPendingInfo`. The legitimate user:
- Cannot sign the refund transaction (the pending-sign ID is registered under the attacker's account, not theirs).
- Cannot re-execute `execute_refund` on Bitcoin (same PSBT → same `btc_pending_id` → "pending info already exist").

The attacker simply refuses to sign. The user's BTC deposit is locked in the bridge's UTXO set with no path to recovery without DAO/Operator intervention. The DAO must reject the refund request, after which the user must re-submit `request_refund` (paying another 2 NEAR anti-spam fee) and wait through the full timelock again. This matches the allowed impact: **Medium — attacker-triggered temporary locking of bridged funds / stuck bridge state requiring operator intervention**.

### Likelihood Explanation

The attack is straightforward and cheap:
1. Refund requests and their timelocks are fully public on-chain.
2. The attacker simply monitors for `RefundRequested` events and calls `execute_refund` as soon as the timelock elapses — no front-running race is needed; the attacker just needs to act before the user.
3. The only cost is the storage deposit for `execute_refund`, which is small and not a meaningful deterrent.
4. The attacker gains nothing financially but can reliably grief any user attempting a BTC refund.

### Recommendation

Store the original requester's `account_id` in `RefundRequest` at `request_refund_callback` time, and enforce in `execute_refund` / `finalize_refund_with_psbt` that only the original requester (or a privileged role) may call it. Alternatively, always use the stored requester's `account_id` as the `BTCPendingInfo.account_id` regardless of who calls `execute_refund`, so the legitimate user retains signing rights.

### Proof of Concept

1. Alice calls `request_refund` for a BTC deposit that was never finalized. `RefundRequest` is stored with `created_at_sec = T`.
2. The timelock (`refund_timelock_sec`) elapses.
3. Attacker (Bob) calls `execute_refund(utxo_storage_key)` before Alice.
4. `finalize_refund_with_psbt` creates `BTCPendingInfo { account_id: bob, ... }` and inserts `btc_pending_id` into Bob's `btc_pending_sign_ids`.
5. Alice calls `execute_refund` → fails: "pending info already exist" (Bitcoin deterministic PSBT).
6. Alice calls `sign_btc_transaction(btc_pending_id, ...)` → fails: `btc_pending_id` is not in Alice's `btc_pending_sign_ids`.
7. Bob does nothing (refuses to sign).
8. Alice's BTC refund is stuck. DAO must reject the refund request; Alice must re-submit `request_refund` (2 NEAR fee) and wait through the full timelock again.

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

**File:** contracts/satoshi-bridge/src/refund.rs (L564-578)
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

        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());
```

**File:** contracts/satoshi-bridge/tests/test_refund.rs (L1554-1560)
```rust
    // (2) After the timelock, bob's call reaches the finalize step but rebuilds the
    // identical tx (same id) and is rejected — no duplicate, no hijack.
    worker.fast_forward(4000).await.unwrap();
    check!(
        context.execute_refund("bob", &key),
        "pending info already exist"
    );
```
