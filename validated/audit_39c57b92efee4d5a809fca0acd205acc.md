Now I have enough context to analyze the full path. Let me verify the exact state transitions.

### Title
User-Controlled `pending_sign_count` Blocks Operator `cancel_withdraw` — (`contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`cancel_withdraw` (DAO/Operator-only) calls `require_pending_sign_capacity(&user_account_id)` before creating the cancel-RBF transaction. Because this check is evaluated against the **user's** `btc_pending_sign_ids`, an unprivileged user can fill that set to the per-account limit after their original withdrawal has been signed, causing every subsequent `cancel_withdraw` call on that withdrawal to panic. The operator loses the ability to cancel a stuck withdrawal without DAO intervention.

---

### Finding Description

**Exact call chain:**

`cancel_withdraw` (public, Operator/DAO-gated) → `require_pending_sign_capacity(&user_account_id)` → panics if `pending_sign_count() >= max_pending_sign_txs`. [1](#0-0) 

`require_pending_sign_capacity` reads `btc_pending_sign_ids.len()` and compares it to the per-account limit (default **1**): [2](#0-1) 

**State transition that opens the window:**

When `sign_btc_transaction_callback` finishes signing all inputs of W1, it removes W1 from `btc_pending_sign_ids` and moves it to `btc_pending_verify_list`. After this point `pending_sign_count() == 0`. [3](#0-2) 

**Attack steps:**

1. User calls `ft_on_transfer` → W1 enters `btc_pending_sign_ids` (count = 1, max = 1).
2. Relayer signs W1 → W1 leaves `btc_pending_sign_ids`, enters `btc_pending_verify_list` (count = 0).
3. W1 is now stuck in PendingVerify (e.g., BTC network congestion).
4. User calls `ft_on_transfer` again → W2 enters `btc_pending_sign_ids` (count = 1; check `0 < 1` passes). [4](#0-3) 

5. Operator calls `cancel_withdraw(W1)` → `require_pending_sign_capacity(user)` evaluates `1 < 1` → **panic "Too many pending sign transactions"**.
6. User repeats step 4 each time W2 is signed, maintaining the block indefinitely as long as they hold nBTC.

---

### Impact Explanation

The UTXOs backing W1 remain locked in the bridge's PendingVerify state. The operator cannot issue the cancel-RBF transaction to reclaim them. This constitutes attacker-triggered temporary locking of bridged funds and a stuck bridge state requiring DAO intervention (calling `set_pending_tx_limit` to raise the user's limit above 1 before retrying `cancel_withdraw`). [5](#0-4) 

---

### Likelihood Explanation

The attack requires only that the user hold enough nBTC to submit a second withdrawal after the first is signed. No privileged access, leaked keys, or external dependencies are needed. The timing window (after W1 is signed, before the operator cancels) is wide because `cancel_withdraw` is only callable after `max_btc_tx_pending_sec` has elapsed. The user can observe on-chain state and act within that window.

---

### Recommendation

Remove `require_pending_sign_capacity` from `cancel_withdraw` (and `cancel_active_utxo_management`). The capacity check exists to prevent unbounded growth of `btc_pending_sign_ids`, but the cancel-RBF path is operator-initiated and must not be blockable by the user. Instead, insert the new cancel-RBF pending ID directly without a capacity pre-check, or exempt operator/DAO callers from the check.

---

### Proof of Concept

```
1. Alice has nBTC. Default max_pending_sign_txs = 1.
2. Alice calls ft_on_transfer(Withdraw, W1).
   → btc_pending_sign_ids = {W1}, pending_sign_count = 1.
3. Relayer calls sign_btc_transaction(W1, 0).
   → sign_btc_transaction_callback removes W1 from btc_pending_sign_ids.
   → btc_pending_sign_ids = {}, pending_sign_count = 0.
   → W1 is now in PendingVerify (stuck, not confirmed on BTC).
4. Alice calls ft_on_transfer(Withdraw, W2).
   → pending_sign_count (0) < max (1) → passes.
   → btc_pending_sign_ids = {W2}, pending_sign_count = 1.
5. Operator calls cancel_withdraw(W1).
   → require_pending_sign_capacity(alice): 1 < 1 → false → PANIC.
6. Repeat step 4 each time W2 is signed to maintain the block.
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

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L198-207)
```rust
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

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L80-85)
```rust
        let max_pending = self.get_max_pending_sign_txs(&sender_id);
        let account = self.internal_unwrap_or_create_mut_account(&sender_id);
        require!(
            account.pending_sign_count() < max_pending,
            "Too many pending sign transactions"
        );
```

**File:** contracts/satoshi-bridge/src/api/management.rs (L190-206)
```rust
    #[payable]
    #[access_control_any(roles(Role::DAO))]
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
