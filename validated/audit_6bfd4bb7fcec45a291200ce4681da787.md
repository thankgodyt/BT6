### Title
User-Controlled `btc_pending_sign_ids` Capacity Blocks DAO `cancel_withdraw` - (`contracts/satoshi-bridge/src/api/bridge.rs`, `contracts/satoshi-bridge/src/rbf/cancel_withdraw.rs`)

---

### Summary

`cancel_withdraw` gates itself on the *user's* pending-sign capacity via `require_pending_sign_capacity(&user_account_id)`. Because `set_rbf_pending_info` — the function that actually creates the cancel RBF entry — never inserts into `btc_pending_sign_ids`, the check is both unnecessary and exploitable: a user who holds any one pending-sign slot (new withdraw or refund) can cause the DAO/Operator's `cancel_withdraw` call to panic with `"Too many pending sign transactions"`.

---

### Finding Description

**Entrypoint — `cancel_withdraw` (DAO/Operator-gated public call):** [1](#0-0) 

The function resolves the *user's* `account_id` from the pending info, then immediately calls:

```rust
self.require_pending_sign_capacity(&user_account_id);
```

**The guard:** [2](#0-1) 

Default limit is `1` for every account: [3](#0-2) 

**Why the check is misplaced — `set_rbf_pending_info` never touches `btc_pending_sign_ids`:** [4](#0-3) 

The cancel RBF entry is inserted only into `btc_pending_infos` and `rbf_txs`. No capacity is consumed. The check guards something that does not happen.

**What fills `btc_pending_sign_ids` (user-reachable):**

- New withdraw via FT transfer: [5](#0-4) 
- Refund execution: [6](#0-5) 

**State transition that empties `btc_pending_sign_ids` for the original withdraw:**

When the original withdraw is fully signed it moves to PendingVerify and is removed from `btc_pending_sign_ids` (confirmed by test assertions at lines 412–418 of `test_satoshi_bridge.rs`). At that point the slot is free and the user can immediately fill it again.

**Concrete attack sequence:**

1. User initiates withdraw → original tx enters PendingSign, added to `btc_pending_sign_ids`.
2. Relayer signs → original tx moves to PendingVerify, removed from `btc_pending_sign_ids` (slot now free).
3. User initiates a second withdraw (or calls `execute_refund` on a separate deposit UTXO) → new tx enters PendingSign, `btc_pending_sign_ids` is full (1/1).
4. `max_btc_tx_pending_sec` elapses.
5. DAO calls `cancel_withdraw(original_btc_pending_verify_id, ...)`.
6. `require_pending_sign_capacity(&user_account_id)` evaluates `1 < 1 → false` → panics `"Too many pending sign transactions"`.
7. DAO cannot cancel; original UTXO remains locked.

---

### Impact Explanation

The DAO/Operator loses the ability to cancel a stuck withdrawal for as long as the user keeps a pending-sign slot occupied. The original UTXO is locked and the cancel RBF path is blocked. This is a stuck-state invariant violation: the protocol's administrative cancel path is gated on an adversarial user's resource.

The DAO has a partial workaround — `set_pending_tx_limit` can raise the user's limit: [7](#0-6) 

However, the user can respond by filling the newly raised capacity with additional pending-sign operations (multiple deposits/refunds), turning this into a sustained griefing loop that requires repeated DAO intervention.

---

### Likelihood Explanation

Any user with a pending withdraw in PendingVerify state can trivially trigger this by initiating a second withdraw (requires only nBTC balance and available UTXOs) or by calling `execute_refund` on a separate deposit UTXO. No special privileges or external dependencies are required. The window is the entire `max_btc_tx_pending_sec` period, giving the user ample time to set up the block before the DAO can act.

---

### Recommendation

Remove `require_pending_sign_capacity(&user_account_id)` from `cancel_withdraw` (and symmetrically from `cancel_active_utxo_management`). The cancel operation does not insert into `btc_pending_sign_ids` — the check is both unnecessary and exploitable. The DAO/Operator's administrative cancel path must not be gated on the user's pending-sign state. [1](#0-0) [8](#0-7) 

---

### Proof of Concept

```
// Setup: alice has a withdraw in PendingVerify (btc_pending_sign_ids is empty)
// alice initiates a second withdraw to fill capacity (btc_pending_sign_ids = {new_tx_id})
// max_btc_tx_pending_sec elapses
// DAO calls cancel_withdraw(original_btc_pending_verify_id, ...)
// → require_pending_sign_capacity(&alice) checks 1 < 1 → false
// → panics: "Too many pending sign transactions"
// → cancel_withdraw reverts; original UTXO remains locked
```

The `set_pending_tx_limit` workaround is insufficient because the user can keep filling the raised capacity with additional pending-sign operations, requiring the DAO to repeatedly intervene.

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

**File:** contracts/satoshi-bridge/src/rbf/mod.rs (L12-43)
```rust
    pub fn set_rbf_pending_info(
        &mut self,
        original_btc_pending_verify_id: &str,
        mut btc_pending_info: BTCPendingInfo,
        psbt: PsbtWrapper,
        is_cancel: bool,
    ) -> String {
        let rbf_psbt_hex = psbt.serialize();
        let btc_pending_id = psbt.get_pending_id();
        btc_pending_info.btc_pending_id.clone_from(&btc_pending_id);
        btc_pending_info.psbt_hex = rbf_psbt_hex;
        require!(
            self.data_mut()
                .btc_pending_infos
                .insert(btc_pending_id.clone(), btc_pending_info.into())
                .is_none(),
            "pending info already exist"
        );
        let rbf_txs = self
            .data_mut()
            .rbf_txs
            .entry(original_btc_pending_verify_id.to_owned())
            .or_default();
        require!(rbf_txs.insert(btc_pending_id.clone()), "Rbf already exist");
        if !is_cancel {
            require!(
                rbf_txs.len() <= self.internal_config().rbf_num_limit.into(),
                "Exceed rbf_num_limit"
            );
        }
        btc_pending_id
    }
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L131-133)
```rust
        self.internal_unwrap_mut_account(&sender_id)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());
```

**File:** contracts/satoshi-bridge/src/refund.rs (L373-375)
```rust
        self.internal_unwrap_mut_account(&caller)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());
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
