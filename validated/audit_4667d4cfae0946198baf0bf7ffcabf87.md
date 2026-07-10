The code is clear. Let me verify the exact state transition to confirm the attack path is reachable.

### Title
Operator `cancel_withdraw` Permanently Blockable by User Filling Their Own Pending-Sign Slot — (`contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`cancel_withdraw` checks `require_pending_sign_capacity` against the **user's** account, not the operator's. Because the cancel RBF is inserted into the user's `btc_pending_sign_ids`, a user who keeps their pending-sign slot(s) full can cause every operator `cancel_withdraw` call to panic, indefinitely blocking the operator's ability to cancel a stuck withdrawal.

---

### Finding Description

`cancel_withdraw` is gated to `Role::DAO | Role::Operator` and is intended to let the protocol forcibly cancel a user's stuck withdrawal via RBF. The function reads the user's account ID from the pending info and immediately calls `require_pending_sign_capacity` on that user: [1](#0-0) 

`require_pending_sign_capacity` panics if `btc_pending_sign_ids.len() >= max_pending`: [2](#0-1) 

The default `max_pending` for any account is **1**: [3](#0-2) 

When a withdrawal is fully signed, `sign_btc_transaction_callback` removes the ID from `btc_pending_sign_ids` and moves it to `btc_pending_verify_list`: [4](#0-3) 

`cancel_withdraw` is only callable on a `WithdrawOriginal` transaction in `PendingVerify` stage (i.e., after signing): [5](#0-4) 

This means the window where `cancel_withdraw` is valid is exactly the window where `btc_pending_sign_ids` is empty — but the user can immediately re-fill it by initiating a new withdrawal.

---

### Impact Explanation

The operator cannot cancel a stuck withdrawal as long as the user keeps their `btc_pending_sign_ids` full. The user's funds in the original withdrawal remain locked in the bridge. The only natural resolution is for the original BTC transaction to confirm on-chain (which may never happen if it is stuck with a low fee), or for the DAO to raise the user's `pending_tx_limit` — but the user can then fill the new slots too.

This matches: **Medium — attacker-triggered temporary locking of bridged funds requiring operator intervention.**

---

### Likelihood Explanation

Exploitable with the **default** `pending_tx_limits` of 1 — no DAO action is required. Any user who has initiated a withdrawal can block operator cancellation by initiating a second withdrawal immediately after the first is signed. The cost to the attacker is the gas fee of each new withdrawal they initiate to keep the slot filled, but this is a small, bounded cost.

---

### Recommendation

Remove the `require_pending_sign_capacity` check from `cancel_withdraw` (and the analogous `cancel_active_utxo_management`). The capacity check exists to limit how many pending-sign entries a user can create; an operator-initiated cancel RBF should not be subject to the user's own slot limit. Alternatively, insert the cancel RBF into a separate operator-owned slot rather than the user's `btc_pending_sign_ids`. [6](#0-5) [7](#0-6) 

---

### Proof of Concept

```
// Setup: default pending_tx_limit = 1 for attacker

// Step 1: attacker initiates withdrawal W1
// → attacker.btc_pending_sign_ids = {W1}

// Step 2: relayer signs W1 (all inputs)
// → sign_btc_transaction_callback removes W1 from btc_pending_sign_ids
// → attacker.btc_pending_sign_ids = {}, btc_pending_verify_list = {W1}
// → W1 is now WithdrawOriginal/PendingVerify — cancel_withdraw(W1) is now valid

// Step 3: attacker immediately initiates withdrawal W2
// → attacker.btc_pending_sign_ids = {W2}  (count = 1)

// Step 4: operator calls cancel_withdraw(W1)
//   user_account_id = W1.account_id = attacker
//   require_pending_sign_capacity(attacker):
//     pending_sign_count() = 1
//     get_max_pending_sign_txs(attacker) = 1  (default)
//     require!(1 < 1, "Too many pending sign transactions")
//     → PANIC — cancel_withdraw reverts

// Attacker repeats step 3 each time the relayer signs their latest withdrawal.
// W1 remains stuck in PendingVerify indefinitely.
```

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L417-421)
```rust
        let user_account_id = self
            .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
            .account_id
            .clone();
        self.require_pending_sign_capacity(&user_account_id);
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

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L194-199)
```rust
    pub fn assert_withdraw_original_pending_verify_tx(&self) {
        match self.state.borrow() {
            PendingInfoState::WithdrawOriginal(state) => state.assert_pending_verify(),
            _ => env::panic_str("Not withdraw original tx"),
        }
    }
```
