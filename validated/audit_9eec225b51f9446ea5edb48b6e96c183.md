Looking at the exact code path in question:

The code path is real and traceable. Here is the full analysis:

---

### Title
DAO/Operator `cancel_withdraw` Blocked by User's Pending-Sign Slot Capacity — (`contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`cancel_withdraw` unconditionally calls `require_pending_sign_capacity` against the **original user's** account before creating the cancel-RBF transaction. When the user's pending-sign slots are already full (e.g., they submitted a second withdrawal after the first), the DAO/Operator call panics with `"Too many pending sign transactions"`, even though the caller is privileged and the check is irrelevant to the caller's authority.

---

### Finding Description

`cancel_withdraw` in `bridge.rs` (lines 285–299):

```rust
pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
    assert_one_yocto();
    let user_account_id = self
        .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
        .account_id
        .clone();
    self.require_pending_sign_capacity(&user_account_id);   // ← checks USER, not caller
    self.cancel_withdraw_chain_specific(...)
}
``` [1](#0-0) 

`require_pending_sign_capacity` (account.rs lines 113–123) checks that the user's `btc_pending_sign_ids.len() < get_max_pending_sign_txs()`. The default limit is **1**. [2](#0-1) 

The reason the check exists is that `cancel_withdraw_chain_specific` (via the `define_rbf_method!` macro) inserts a new `WithdrawCancelRbf` entry into `account.btc_pending_sign_ids`:

```rust
self.internal_unwrap_mut_account(&account_id)
    .btc_pending_sign_ids
    .insert(btc_pending_id.clone());
``` [3](#0-2) 

So the check is technically load-bearing — but it is applied to the **user's** slot budget, not the caller's, and there is no bypass for the privileged DAO/Operator role.

**Concrete reachable state:**

| Slot | Entry | Stage |
|---|---|---|
| `btc_pending_sign_ids` | withdrawal #2 | PendingSign |
| `btc_pending_verify_list` | withdrawal #1 | PendingVerify ← target of cancel |

With `pending_tx_limit = 1` (the default for every account):

1. User submits withdrawal #1 → signed → moves to `PendingVerify`.
2. User submits withdrawal #2 → sits in `PendingSign` (fills the one slot).
3. DAO calls `cancel_withdraw(withdrawal_1_id, ...)`.
4. `require_pending_sign_capacity(&user_account_id)` → `1 < 1` is false → **panic**: `"Too many pending sign transactions"`. [4](#0-3) [5](#0-4) 

The same flaw exists identically in `cancel_active_utxo_management` (bridge.rs lines 411–428). [6](#0-5) 

---

### Impact Explanation

The DAO/Operator cannot cancel a pending-verify withdrawal when the same user's pending-sign slot is occupied. The user's nBTC remains locked in the bridge for the duration. This is a **stuck bridge state requiring operator intervention** — specifically, the DAO must first call a management function to raise the user's `pending_tx_limit`, then retry the cancel. This is an unexpected extra step that violates the invariant that the DAO can unconditionally cancel any pending withdrawal.

The locking is **not permanent** in the general case: once withdrawal #2 is signed and advances to PendingVerify, the slot is freed and the cancel can proceed. However, if MPC signing is unavailable (network outage, key rotation), withdrawal #2 stays in PendingSign indefinitely, and the DAO is blocked from canceling withdrawal #1 for the entire outage window.

Impact category: **Low — publicly reachable invariant-violation / stuck state requiring operator intervention**, with a secondary **Medium** dimension (stuck bridge state) if MPC signing is simultaneously unavailable.

---

### Likelihood Explanation

- Default `pending_tx_limit` is 1 for every account; no special configuration needed.
- A user only needs to submit two withdrawals in sequence (normal behavior, not malicious) to reach this state.
- The DAO/Operator cancel path is exercised precisely when withdrawals are stuck, making the collision likely in practice.

---

### Recommendation

Skip `require_pending_sign_capacity` when the caller holds `Role::DAO` or `Role::Operator`, since the cancel is a privileged administrative action, not a user-initiated transaction. Alternatively, exempt cancel-RBF entries from the per-user pending-sign limit entirely, since they are protocol-initiated and do not represent user-controlled spending.

---

### Proof of Concept

```rust
// Pseudocode unit test
let mut contract = setup_contract();
contract.set_pending_tx_limit(&user, 1);

// Withdrawal #1: PendingSign → PendingVerify
let w1_id = create_withdrawal(&mut contract, &user, ...);
advance_to_pending_verify(&mut contract, w1_id.clone());

// Withdrawal #2: PendingSign (fills the one slot)
let _w2_id = create_withdrawal(&mut contract, &user, ...);
// user.btc_pending_sign_ids.len() == 1 now

// DAO tries to cancel withdrawal #1
set_caller_as_dao();
// Panics: "Too many pending sign transactions"
contract.cancel_withdraw(w1_id, vec![change_output]);
``` [1](#0-0) [2](#0-1)

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L411-428)
```rust
    pub fn cancel_active_utxo_management(
        &mut self,
        original_btc_pending_verify_id: String,
        output: Vec<TxOut>,
    ) {
        assert_one_yocto();
        let user_account_id = self
            .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
            .account_id
            .clone();
        self.require_pending_sign_capacity(&user_account_id);
        self.cancel_active_utxo_management_chain_specific(
            user_account_id,
            original_btc_pending_verify_id,
            output,
            None,
        );
    }
```

**File:** contracts/satoshi-bridge/src/account.rs (L99-101)
```rust
    pub fn pending_sign_count(&self) -> u32 {
        u32::try_from(self.btc_pending_sign_ids.len()).unwrap_or(u32::MAX)
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

**File:** contracts/satoshi-bridge/src/bitcoin_utils/contract_methods.rs (L34-36)
```rust
            self.internal_unwrap_mut_account(&account_id)
                .btc_pending_sign_ids
                .insert(btc_pending_id.clone());
```
