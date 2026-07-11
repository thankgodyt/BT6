### Title
Unprivileged User Can Permanently Block Operator `cancel_withdraw` by Maintaining a Concurrent Pending-Sign Transaction — (`contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`cancel_withdraw` (DAO/Operator-only) calls `require_pending_sign_capacity(&user_account_id)` before creating the cancel-RBF transaction. Because this check is against the **user's current** `btc_pending_sign_ids` count — not the withdrawal being cancelled — a user can block the operator indefinitely by keeping a second, unrelated withdrawal in the pending-sign state.

---

### Finding Description

`cancel_withdraw` in `bridge.rs` is restricted to DAO/Operator callers, but at line 291 it checks the **target user's** pending-sign capacity: [1](#0-0) 

`require_pending_sign_capacity` panics when `pending_sign_count() >= max_pending_sign_txs`: [2](#0-1) 

The default per-account limit is **1**: [3](#0-2) 

`cancel_withdraw` can only target a withdrawal that has already been fully signed and moved to PendingVerify (enforced by `assert_withdraw_original_pending_verify_tx()` inside `internal_cancel_withdraw`): [4](#0-3) 

When a transaction is fully signed and transitions to PendingVerify, it is **removed** from `btc_pending_sign_ids`: [5](#0-4) 

This frees the user's pending-sign slot. The user can immediately submit a new withdrawal via `ft_on_transfer`, re-occupying that slot. Now the operator's `cancel_withdraw` call on the original (PendingVerify) withdrawal hits `require_pending_sign_capacity`, finds `count = 1`, and panics because `1 < 1` is false.

The user can sustain this state indefinitely: each time the relayer signs the blocking withdrawal, the user submits another one.

---

### Impact Explanation

The bridge UTXOs consumed by the stuck withdrawal remain locked in an unresolvable PendingVerify state. The operator's only recovery path — `cancel_withdraw` — is permanently blocked. The bridge cannot reclaim those UTXOs for future withdrawals, causing a permanent reduction in available bridge liquidity proportional to the locked UTXO set.

This matches: **Medium — attacker-triggered temporary/permanent locking of bridged funds; stuck bridge state requiring operator intervention.**

---

### Likelihood Explanation

The attack requires only:
1. A normal `ft_on_transfer` Withdraw call (public, no privilege needed).
2. Waiting for the relayer to sign the first withdrawal (normal bridge operation).
3. Submitting a second `ft_on_transfer` Withdraw call to re-occupy the pending-sign slot.

No leaked keys, no governance control, no external dependencies. The default limit of 1 means a single concurrent withdrawal is sufficient. The attack is cheap and repeatable.

---

### Recommendation

Remove `require_pending_sign_capacity` from `cancel_withdraw`. The capacity check exists to prevent the user's pending-sign set from growing unboundedly when creating a new RBF entry; however, the cancel-RBF entry is keyed to the **original** pending-verify ID and is tracked separately in `rbf_txs`, not in `btc_pending_sign_ids`. The check is both unnecessary and harmful in this context.

Alternatively, if the check is intentional (to limit total concurrent sign work), scope it so that it is skipped when the caller holds the DAO or Operator role, or check only the cancel-RBF slot rather than the user's general pending-sign count.

---

### Proof of Concept

```
1. Operator grants Alice the default limit of 1 pending-sign tx (the default).

2. Alice calls ft_on_transfer(Withdraw, W1) → W1 added to alice.btc_pending_sign_ids.
   alice.pending_sign_count() == 1.

3. Relayer calls sign_btc_transaction(W1, ...) for all inputs → W1 fully signed,
   removed from btc_pending_sign_ids, added to btc_pending_verify_list.
   alice.pending_sign_count() == 0.

4. Alice immediately calls ft_on_transfer(Withdraw, W2) → W2 added to btc_pending_sign_ids.
   alice.pending_sign_count() == 1.

5. Operator calls cancel_withdraw(W1, output):
   - Looks up W1 → user_account_id = alice.
   - Calls require_pending_sign_capacity(&alice):
       alice.pending_sign_count() = 1
       get_max_pending_sign_txs(&alice) = 1
       require!(1 < 1, "Too many pending sign transactions") → PANICS.

6. cancel_withdraw reverts. W1's UTXOs remain locked.
   Alice repeats step 4 whenever W2 is signed, maintaining the block indefinitely.
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

**File:** contracts/satoshi-bridge/src/rbf/cancel_withdraw.rs (L36-37)
```rust
        original_tx_btc_pending_info.assert_not_canceled();
        original_tx_btc_pending_info.assert_withdraw_original_pending_verify_tx();
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
