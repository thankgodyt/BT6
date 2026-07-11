### Title
User Can Block Operator's `cancel_withdraw` by Filling Own `btc_pending_sign_ids` — (`contracts/satoshi-bridge/src/api/bridge.rs`, `contracts/satoshi-bridge/src/account.rs`)

---

### Summary

`cancel_withdraw` checks `require_pending_sign_capacity` against the **target user's** account, not the caller's. A user can fill their own `btc_pending_sign_ids` to the per-account limit (default: 1) by calling the public `withdraw_rbf` function after their original withdraw is signed. This causes every subsequent Operator `cancel_withdraw` call on that withdraw to revert with `"Too many pending sign transactions"`, blocking the privileged cancel path for as long as the user can keep the slot occupied.

---

### Finding Description

`cancel_withdraw` is an Operator/DAO-gated function that creates a new `WithdrawCancelRbf` pending-sign entry for the user's account. Before creating it, it checks that the user has capacity:

```rust
// contracts/satoshi-bridge/src/api/bridge.rs  lines 285-299
pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
    assert_one_yocto();
    let user_account_id = self
        .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
        .account_id
        .clone();
    self.require_pending_sign_capacity(&user_account_id);   // ← checks TARGET user
    self.cancel_withdraw_chain_specific(...)
}
``` [1](#0-0) 

`require_pending_sign_capacity` enforces `pending_sign_count() < max`, where the default max is **1**:

```rust
// contracts/satoshi-bridge/src/account.rs  lines 113-123
pub fn require_pending_sign_capacity(&self, account_id: &AccountId) {
    require!(
        self.get_account(account_id)...
            .pending_sign_count()
            < self.get_max_pending_sign_txs(account_id),  // default = 1
        "Too many pending sign transactions"
    );
}
``` [2](#0-1) 

The lifecycle of `btc_pending_sign_ids` is:

- **Added** when a withdraw (or RBF) is initiated.
- **Removed** in `sign_btc_transaction_callback` when all inputs are signed and the entry moves to `PendingVerify`. [3](#0-2) 

`cancel_withdraw` is only callable once the original withdraw is in `WithdrawOriginal / PendingVerify` state (i.e., already signed and removed from `btc_pending_sign_ids`): [4](#0-3) 

At that point `btc_pending_sign_ids` is empty (count = 0). The public `withdraw_rbf` function — which has **no role restriction** — also calls `require_pending_sign_capacity` against the **caller** (not the target), so it passes when count = 0, and then inserts a new `WithdrawUserRbf` entry into `btc_pending_sign_ids`: [5](#0-4) [6](#0-5) 

After this, count = 1 = max. The Operator's `cancel_withdraw` call now evaluates `1 < 1 = false` and reverts.

---

### Impact Explanation

The Operator cannot cancel a stuck withdrawal while the user keeps `btc_pending_sign_ids` at capacity. The bridge UTXOs locked in the original withdraw remain inaccessible. The user can sustain the block by:

1. **RBF loop**: After the relayer signs `withdraw_rbf_1`, call `withdraw_rbf` again to create `withdraw_rbf_2`, etc. — repeatable until `rbf_num_limit` is exhausted. [7](#0-6) 

2. **New withdraw**: Initiate a fresh withdraw with a different UTXO (obtained from a new deposit), keeping `btc_pending_sign_ids` perpetually full.

Once `rbf_num_limit` is exhausted and the user has no more UTXOs, the Operator can proceed. The DAO can also call `set_pending_tx_limit(user, Some(large_value))` as an emergency workaround: [8](#0-7) 

Impact: **Medium** — attacker-triggered temporary locking of bridged funds and stuck bridge state requiring operator/DAO intervention.

---

### Likelihood Explanation

The attack requires only:
1. A user with a stuck withdraw (already signed, in PendingVerify).
2. The user calling the public `withdraw_rbf` (paying a marginally higher BTC gas fee) before the Operator calls `cancel_withdraw`.

No special privileges, no leaked keys, no external dependencies. The user has a rational motive: they may prefer the original BTC transaction to eventually confirm on-chain rather than be canceled back to the bridge's change address.

---

### Recommendation

Remove the `require_pending_sign_capacity` check from `cancel_withdraw` (and `cancel_active_utxo_management`). The cancel RBF is Operator/DAO-initiated and its new pending-sign slot should not be gated by the target user's capacity. Alternatively, skip the capacity check when the caller holds the `Operator` or `DAO` role, or attribute the cancel RBF slot to the bridge contract account rather than the user.

---

### Proof of Concept

```
1. Alice deposits BTC → receives nBTC.
2. Alice calls ft_transfer_call → do_withdraw (withdraw1).
   btc_pending_sign_ids = {withdraw1}, count=1.
3. Relayer calls sign_btc_transaction(withdraw1, 0).
   → sign_btc_transaction_callback removes withdraw1 from btc_pending_sign_ids.
   btc_pending_sign_ids = {}, count=0.
4. Alice calls withdraw_rbf(withdraw1, higher_gas_output).
   → require_pending_sign_capacity(alice): 0 < 1 ✓
   → inserts withdraw1_rbf into btc_pending_sign_ids.
   btc_pending_sign_ids = {withdraw1_rbf}, count=1.
5. Operator calls cancel_withdraw(withdraw1, cancel_output).
   → require_pending_sign_capacity(alice): 1 < 1 ✗
   → REVERT: "Too many pending sign transactions"
6. Repeat step 4 each time the relayer signs the RBF, until rbf_num_limit
   is reached. After that, use a new withdraw with a fresh UTXO.
```

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L258-274)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn withdraw_rbf(
        &mut self,
        original_btc_pending_verify_id: String,
        output: Vec<TxOut>,
        chain_specific_data: Option<ChainSpecificData>,
    ) {
        let account_id = env::predecessor_account_id();
        self.require_pending_sign_capacity(&account_id);

        self.withdraw_rbf_chain_specific(
            account_id,
            original_btc_pending_verify_id,
            output,
            chain_specific_data,
        );
    }
```

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

**File:** contracts/satoshi-bridge/src/account.rs (L105-123)
```rust
    pub fn get_max_pending_sign_txs(&self, account_id: &AccountId) -> u32 {
        self.data()
            .pending_tx_limits
            .get(account_id)
            .copied()
            .unwrap_or(1)
    }

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

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L197-207)
```rust
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

**File:** contracts/satoshi-bridge/src/bitcoin_utils/contract_methods.rs (L34-36)
```rust
            self.internal_unwrap_mut_account(&account_id)
                .btc_pending_sign_ids
                .insert(btc_pending_id.clone());
```

**File:** contracts/satoshi-bridge/src/rbf/mod.rs (L36-41)
```rust
        if !is_cancel {
            require!(
                rbf_txs.len() <= self.internal_config().rbf_num_limit.into(),
                "Exceed rbf_num_limit"
            );
        }
```

**File:** contracts/satoshi-bridge/src/api/management.rs (L192-206)
```rust
    pub fn set_pending_tx_limit(&mut self, account_id: AccountId, max_pending: Option<u32>) {
        assert_one_yocto();
        if let Some(max_pending) = max_pending {
            require!(max_pending >= 1, "Invalid max_pending value");
            self.data_mut()
                .pending_tx_limits
                .insert(account_id, max_pending);
        } else {
            let prev = self.data_mut().pending_tx_limits.remove(&account_id);
            require!(
                prev.is_some(),
                format!("Invalid account_id: {}", account_id)
            );
        }
    }
```
