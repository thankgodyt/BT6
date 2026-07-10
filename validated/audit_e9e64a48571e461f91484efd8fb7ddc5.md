### Title
Operator `cancel_withdraw` Blocked by User Filling Their Own Pending Sign Capacity — (`contracts/satoshi-bridge/src/api/bridge.rs`, `contracts/satoshi-bridge/src/rbf/cancel_withdraw.rs`)

### Summary

`cancel_withdraw` (operator-only) calls `require_pending_sign_capacity(&user_account_id)` — checking the **withdraw owner's** pending sign slot count — before creating the cancel-RBF transaction. A user can fill their own slot with a refund pending sign tx, causing the operator's call to panic with "Too many pending sign transactions" and temporarily preventing cancellation of a stuck withdraw.

### Finding Description

The public API entry point is:

```rust
// contracts/satoshi-bridge/src/api/bridge.rs:285-299
pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
    assert_one_yocto();
    let user_account_id = self
        .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
        .account_id
        .clone();
    self.require_pending_sign_capacity(&user_account_id);   // ← checks withdraw OWNER
    self.cancel_withdraw_chain_specific(...)
}
``` [1](#0-0) 

`require_pending_sign_capacity` enforces:

```rust
// contracts/satoshi-bridge/src/account.rs:113-123
pub fn require_pending_sign_capacity(&self, account_id: &AccountId) {
    require!(
        self.get_account(account_id)...pending_sign_count()
            < self.get_max_pending_sign_txs(account_id),  // default = 1
        "Too many pending sign transactions"
    );
}
``` [2](#0-1) 

The default limit is 1 for any account without a custom entry: [3](#0-2) 

**Lifecycle of `btc_pending_sign_ids`:**

When the relayer fully signs the original withdraw, `sign_btc_transaction_callback` removes it from `btc_pending_sign_ids` and moves it to `btc_pending_verify_list`:

```rust
// contracts/satoshi-bridge/src/chain_signature.rs:195-207
btc_pending_info.to_pending_verify_stage();
let account = self.internal_unwrap_mut_account(&account_id);
require!(account.btc_pending_sign_ids.remove(&btc_pending_sign_id), "Internal error");
if is_original_tx {
    account.btc_pending_verify_list.insert(btc_pending_sign_id.clone());
}
``` [4](#0-3) 

`cancel_withdraw` requires the original tx to be in PendingVerify stage (line 37 of `cancel_withdraw.rs`), so at the time the operator calls it, the original withdraw is already out of `btc_pending_sign_ids`. The slot is free — **unless** the user has filled it with another pending sign tx. [5](#0-4) 

`finalize_refund_with_psbt` inserts a refund tx into the user's `btc_pending_sign_ids`:

```rust
// contracts/satoshi-bridge/src/refund.rs:342, 373-375
self.require_pending_sign_capacity(&caller);
...
self.internal_unwrap_mut_account(&caller)
    .btc_pending_sign_ids
    .insert(btc_pending_id.clone());
``` [6](#0-5) [7](#0-6) 

Since the original withdraw is in PendingVerify (slot freed), the user can successfully call `execute_refund`, which passes `require_pending_sign_capacity` and inserts a refund pending sign tx into `btc_pending_sign_ids`. Now `pending_sign_count() = 1 = get_max_pending_sign_txs(user)`, and the operator's subsequent `cancel_withdraw` call panics.

### Impact Explanation

The operator cannot cancel a stuck withdraw for as long as the user maintains a pending sign tx in their slot. The user's bridged funds remain locked in the stuck `WithdrawOriginal(PendingVerify)` state. This matches **Medium — attacker-triggered temporary locking of bridged funds requiring operator intervention**.

### Likelihood Explanation

The preconditions are realistic and fully public:
1. User initiates a withdraw (normal bridge use).
2. Relayer signs it; it moves to PendingVerify (normal operation).
3. The withdraw gets stuck on-chain (BTC mempool congestion, etc.).
4. User calls `execute_refund` on any of their deposit UTXOs — a fully public call — filling their pending sign slot.
5. Operator calls `cancel_withdraw` → panic.

No privileged access, leaked keys, or external dependency compromise is required. The user only needs a valid deposit UTXO to execute a refund, which is a normal bridge operation.

### Recommendation

The capacity check in `cancel_withdraw` is intended to ensure there is room in the user's `btc_pending_sign_ids` for the new `WithdrawCancelRbf` entry (inserted by `cancel_withdraw_chain_specific` via the `define_rbf_method!` macro). The fix should decouple operator-initiated cancels from the user's capacity limit. Options:

1. **Skip the capacity check for operator cancels** and instead allow the cancel-RBF to exceed the normal limit (since it is replacing an existing stuck tx, not adding a net-new one).
2. **Temporarily bump the user's limit by 1** for the duration of the cancel operation.
3. **Check and enforce capacity inside `internal_cancel_withdraw`** only after verifying the cancel is operator-initiated, with an explicit allowance for one extra slot.

### Proof of Concept

```
State: user has pending_tx_limit = 1 (default)

1. user calls ft_transfer_call (withdraw) → btc_pending_sign_ids = {withdraw_id}
2. relayer calls sign_btc_transaction (all inputs) →
       btc_pending_sign_ids = {}
       btc_pending_verify_list = {withdraw_id}   // PendingVerify
3. withdraw gets stuck (max_btc_tx_pending_sec elapses without BTC confirmation)
4. user calls execute_refund (on a separate deposit UTXO) →
       btc_pending_sign_ids = {refund_id}         // slot now full
5. operator calls cancel_withdraw(withdraw_id, ...) →
       require_pending_sign_capacity(&user_account_id):
           pending_sign_count() = 1, limit = 1
           1 < 1 → false → panic "Too many pending sign transactions"
```

The operator cannot cancel the stuck withdraw until the relayer signs the refund tx (freeing the slot), during which time the user's bridged funds remain locked.

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L285-299)
```rust
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

**File:** contracts/satoshi-bridge/src/account.rs (L105-111)
```rust
    pub fn get_max_pending_sign_txs(&self, account_id: &AccountId) -> u32 {
        self.data()
            .pending_tx_limits
            .get(account_id)
            .copied()
            .unwrap_or(1)
    }
```

**File:** contracts/satoshi-bridge/src/account.rs (L113-123)
```rust
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

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L195-207)
```rust
                btc_pending_info.to_pending_verify_stage();

                let is_original_tx = btc_pending_info.get_original_tx_id().is_none();
                let account = self.internal_unwrap_mut_account(&account_id);
                require!(
                    account.btc_pending_sign_ids.remove(&btc_pending_sign_id),
                    "Internal error"
                );
                if is_original_tx {
                    account
                        .btc_pending_verify_list
                        .insert(btc_pending_sign_id.clone());
                }
```

**File:** contracts/satoshi-bridge/src/rbf/cancel_withdraw.rs (L36-37)
```rust
        original_tx_btc_pending_info.assert_not_canceled();
        original_tx_btc_pending_info.assert_withdraw_original_pending_verify_tx();
```

**File:** contracts/satoshi-bridge/src/refund.rs (L342-342)
```rust
        self.require_pending_sign_capacity(&caller);
```

**File:** contracts/satoshi-bridge/src/refund.rs (L373-375)
```rust
        self.internal_unwrap_mut_account(&caller)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());
```
