### Title
Anyone Can Execute a Pending Refund Request, Hijacking the BTCPendingInfo Owner - (File: `contracts/satoshi-bridge/src/refund.rs`)

### Summary
The `execute_refund` entry point (whose shared pre-execution logic lives in `resolve_execute_refund_timelock` and `finalize_refund_with_psbt`) imposes no restriction on *who* may call it. Any unprivileged NEAR account can trigger execution of any pending refund request once the timelock has elapsed. The caller is recorded as the `account_id` owner of the resulting `BTCPendingInfo`, displacing the original requester from the refund lifecycle.

### Finding Description
`resolve_execute_refund_timelock` reads `env::predecessor_account_id()` only to decide which timelock duration to apply — privileged callers (DAO / RefundOperator) get a shorter wait, everyone else gets the longer `unsafe_refund_timelock_sec`. There is no `require` that restricts the call to the original requester or any specific party:

```rust
// contracts/satoshi-bridge/src/refund.rs  lines 206-228
let caller = env::predecessor_account_id();
let is_privileged =
    self.acl_has_any_role(vec![Role::DAO.into(), Role::RefundOperator.into()], caller);
...
if is_privileged { 0 } else { config.unsafe_refund_timelock_sec }
```

After the timelock check passes, `finalize_refund_with_psbt` is called with that same `caller` as the owner of the new `BTCPendingInfo`:

```rust
// contracts/satoshi-bridge/src/refund.rs  lines 315-401
pub(crate) fn finalize_refund_with_psbt(
    &mut self,
    caller: AccountId,          // ← whoever called execute_refund
    ...
) {
    ...
    if !self.check_account_exists(&caller) {
        self.internal_set_account(&caller, crate::Account::new(&caller));
    }
    self.require_pending_sign_capacity(&caller);

    let btc_pending_info = BTCPendingInfo {
        account_id: caller.clone(),   // ← attacker's account recorded
        ...
    };
    ...
    self.internal_unwrap_mut_account(&caller)
        .btc_pending_sign_ids
        .insert(btc_pending_id.clone());
```

The BTC refund destination is fixed to `refund_request.refund_address` (set at request time), so the on-chain Bitcoin output is unaffected. However, the NEAR-side `BTCPendingInfo` — which governs the signing, verification, and finalization lifecycle — is now owned by the attacker, not the original requester.

### Impact Explanation
- The attacker forces the refund to execute at a time of their choosing (immediately after the timelock), removing the original requester's ability to decide when to proceed.
- The attacker's account becomes `account_id` in `BTCPendingInfo`. All subsequent lifecycle operations (`verify_refund_finalize_callback` cleanup at line 489) operate on the attacker's account, not the original requester's.
- The original requester's NEAR account has no `BTCPendingInfo` entry and cannot participate in or monitor the refund finalization.
- If the attacker's account is at its `pending_sign_count` limit, the call reverts, effectively blocking the refund from being executed by anyone until the attacker's capacity frees up — a temporary locking of the refund flow.

This matches: **Medium — attacker-triggered temporary locking of bridged funds / bypass of bridge policies**.

### Likelihood Explanation
Any NEAR account can call `execute_refund` with a known `utxo_storage_key` (emitted publicly in the `RefundRequested` event). No special role, key, or capital is required beyond the small attached storage deposit. The attack is trivially repeatable on every pending refund request once its timelock expires.

### Recommendation
Restrict `execute_refund` so that only the original requester (the account that called `request_refund`) or a privileged role (DAO / RefundOperator) may execute it. Store the requester's `AccountId` in `RefundRequest` at request time and enforce it:

```rust
// In resolve_execute_refund_timelock or the public execute_refund entry point:
let caller = env::predecessor_account_id();
let is_privileged = self.acl_has_any_role(..., caller.clone());
require!(
    is_privileged || caller == refund_request.requester,
    "Only the original requester or a privileged role may execute this refund"
);
```

### Proof of Concept
1. Alice calls `request_refund(deposit_msg, refund_address="bc1qAlice...", ...)`. The `RefundRequested` event is emitted with the `utxo_storage_key`.
2. The `unsafe_refund_timelock_sec` elapses.
3. Bob (any NEAR account) calls `execute_refund(utxo_storage_key, ...)` with the required storage deposit.
4. `resolve_execute_refund_timelock` returns `config.unsafe_refund_timelock_sec` (timelock already passed → check succeeds).
5. `finalize_refund_with_psbt` is called with `caller = Bob`. Bob's account is created if needed; the `BTCPendingInfo` is inserted with `account_id = Bob`.
6. Alice's account has no `BTCPendingInfo`. Bob now controls the signing and finalization lifecycle of Alice's refund. Alice cannot call `verify_refund_finalize` through her own account's pending list.
7. The BTC is still sent to `bc1qAlice...`, but Alice has lost all NEAR-side control over the refund process, and Bob can block finalization by keeping his pending capacity full. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L315-345)
```rust
    pub(crate) fn finalize_refund_with_psbt(
        &mut self,
        caller: AccountId,
        mut refund_request: RefundRequest,
        psbt: PsbtWrapper,
        refund_amount: u128,
        utxo_storage_key: String,
    ) {
        let gas_fee = refund_request.gas_fee;
        let refund_address = refund_request.refund_address.clone();

        let deposit_msg = refund_request.deposit_msg();
        let path = get_deposit_path(&deposit_msg);
        let vutxo = VUTXO::Current(UTXO {
            path,
            tx_bytes: refund_request.tx_bytes.0.clone(),
            vout: refund_request.vout,
            balance: u64::try_from(refund_request.amount)
                .unwrap_or_else(|_| env::panic_str("Amount overflow")),
        });

        let psbt_hex = psbt.serialize();
        let btc_pending_id = psbt.get_pending_id();

        if !self.check_account_exists(&caller) {
            self.internal_set_account(&caller, crate::Account::new(&caller));
        }
        self.require_pending_sign_capacity(&caller);

        let btc_pending_info = BTCPendingInfo {
            account_id: caller.clone(),
```

**File:** contracts/satoshi-bridge/src/refund.rs (L366-401)
```rust
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

        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());

        Event::RefundExecuted {
            utxo_storage_key: utxo_storage_key.clone(),
            amount: refund_request.amount.into(),
            refund_address,
        }
        .emit();

        Event::GenerateBtcPendingInfo {
            account_id: &caller,
            btc_pending_id: &btc_pending_id,
        }
        .emit();

        // Keep the request (so `execute_refund` can be called again to re-create
        // the transaction) but mark it executed; it is removed only when the
        // refund is finalized in `verify_refund_finalize`.
        refund_request.executed = true;
        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());
```

**File:** contracts/satoshi-bridge/src/refund.rs (L486-494)
```rust

        // Clean up: remove pending info
        self.internal_remove_btc_pending_info(&tx_id);
        self.internal_unwrap_mut_account(&account_id)
            .btc_pending_verify_list
            .remove(&tx_id);

        true
    }
```
