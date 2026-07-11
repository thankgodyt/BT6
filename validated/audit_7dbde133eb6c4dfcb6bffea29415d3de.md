I have all the code needed to evaluate this claim. Let me trace the exact path.

## Code Trace

**`pending_sign_count()` only counts `btc_pending_sign_ids`:** [1](#0-0) 

**`require_pending_sign_capacity` enforces the limit against that count:** [2](#0-1) 

**`create_btc_pending_info` (called by `ft_on_transfer`) uses the same check:** [3](#0-2) 

**`sign_btc_transaction_callback` — the asymmetry is real and exact:** [4](#0-3) 

When all inputs are signed, the tx is removed from `btc_pending_sign_ids`. It is only inserted into `btc_pending_verify_list` when `is_original_tx` is true. For RBF transactions (`WithdrawUserRbf`, `WithdrawCancelRbf`), `get_original_tx_id()` returns `Some(...)`, so `is_original_tx = false` and the RBF tx is **never** added to `btc_pending_verify_list`. [5](#0-4) 

**`withdraw_rbf` is unprivileged (no `#[access_control_any]`) and callable by any user:** [6](#0-5) 

**`sign_btc_transaction` is also unprivileged (no `#[access_control_any]`):** [7](#0-6) 

**`define_rbf_method!` inserts the RBF tx into `btc_pending_sign_ids`:** [8](#0-7) 

---

## Reachability Analysis

The full call sequence is:

1. Attacker calls `ft_transfer_call(bridge, amount1, ...)` → `ft_on_transfer` → `create_btc_pending_info` → `btc_pending_sign_ids = {tx1}` (count=1, limit=1, blocked)
2. Attacker (or anyone) calls `sign_btc_transaction(tx1, ...)` → all inputs signed → `btc_pending_sign_ids = {}`, `btc_pending_verify_list = {tx1}` (count=0)
3. Attacker calls `withdraw_rbf(tx1, ...)` → capacity check passes (count=0) → `btc_pending_sign_ids = {rbf1}` (count=1)
4. Attacker calls `sign_btc_transaction(rbf1, ...)` → all inputs signed → `btc_pending_sign_ids = {}`, `btc_pending_verify_list = {tx1}` (count=0, rbf1 NOT added)
5. Attacker calls `ft_transfer_call(bridge, amount2, ...)` → capacity check passes (count=0) → `btc_pending_sign_ids = {tx2}` — **limit bypassed**

Steps 3–5 can be repeated. Each iteration requires the attacker to supply more nBTC (which is locked in the bridge), but each new withdrawal also locks a fresh set of bridge UTXOs.

`sign_btc_transaction` has no role guard, so the attacker can drive the signing themselves. `withdraw_rbf` checks `account_id == predecessor_account_id` inside `internal_withdraw_rbf`, which is satisfied since the attacker is calling on their own withdrawal. [9](#0-8) 

---

## Impact Assessment

The per-account limit (default 1) exists to bound how many bridge UTXOs a single account can lock simultaneously. After the RBF signing completes, `btc_pending_sign_ids` is empty but the account still has active obligations: the original tx and the RBF tx are both in `PendingVerify` in `btc_pending_infos`. The capacity check is blind to these because it only reads `btc_pending_sign_ids.len()`.

The attacker can therefore hold N original-tx + N RBF-tx in PendingVerify while simultaneously opening a new PendingSign withdrawal, locking 2N+1 sets of bridge UTXOs instead of the intended 1. With sufficient nBTC, this exhausts bridge UTXO liquidity and blocks other users from withdrawing.

This matches the allowed Medium impact: **bypass of bridge limits or policies, attacker-triggered temporary locking of bridged funds**.

---

### Title
RBF signing removes tx from `btc_pending_sign_ids` without inserting into `btc_pending_verify_list`, allowing per-account pending-sign limit bypass — (`contracts/satoshi-bridge/src/account.rs`, `contracts/satoshi-bridge/src/chain_signature.rs`)

### Summary
After a user-RBF withdrawal is fully signed, it is removed from `btc_pending_sign_ids` but not inserted into `btc_pending_verify_list`. Because `pending_sign_count()` only measures `btc_pending_sign_ids.len()`, the capacity guard drops to zero and a new `ft_on_transfer(Withdraw)` succeeds, bypassing the per-account limit of 1 concurrent pending-sign transaction.

### Finding Description
`sign_btc_transaction_callback` unconditionally removes the signed tx from `btc_pending_sign_ids` and conditionally inserts it into `btc_pending_verify_list` only when `is_original_tx` is true. RBF transactions (`WithdrawUserRbf`, `WithdrawCancelRbf`) have `get_original_tx_id()` returning `Some(...)`, so `is_original_tx = false` and they are never tracked in `btc_pending_verify_list`. The capacity guard `require_pending_sign_capacity` reads only `btc_pending_sign_ids.len()`, so after RBF signing completes the guard sees count=0 and permits a new withdrawal even though the account still has active PendingVerify obligations.

### Impact Explanation
An attacker with nBTC can repeatedly cycle through: sign original → RBF → sign RBF → new withdrawal, locking additional bridge UTXOs on each iteration. With sufficient nBTC the attacker can exhaust bridge UTXO liquidity, preventing legitimate users from withdrawing. The attacker's own nBTC is locked proportionally, making this a griefing/DoS attack rather than direct theft.

### Likelihood Explanation
Medium. The attacker needs nBTC and must drive the signing flow themselves (both `sign_btc_transaction` and `withdraw_rbf` are unprivileged). The chain-signature call costs gas but is not otherwise gated. The exploit is deterministic and locally testable.

### Recommendation
`pending_sign_count()` should account for all active obligations, not just `btc_pending_sign_ids`. One approach: also count entries in `btc_pending_verify_list` (and any RBF PendingVerify entries linked to those originals). Alternatively, track a separate `active_obligation_count` field that is incremented on any new pending-sign creation and decremented only when the obligation is fully resolved (verified on-chain or cleaned up), regardless of whether it is an original or RBF tx.

### Proof of Concept
State-level test asserting:
1. Alice withdraws → `btc_pending_sign_ids = {tx1}`, count=1
2. Sign tx1 → `btc_pending_sign_ids = {}`, `btc_pending_verify_list = {tx1}`, count=0
3. Alice calls `withdraw_rbf(tx1)` → `btc_pending_sign_ids = {rbf1}`, count=1
4. Sign rbf1 → `btc_pending_sign_ids = {}`, `btc_pending_verify_list = {tx1}` (rbf1 absent), count=0
5. Alice calls `ft_transfer_call` again → **succeeds** (should be blocked), `btc_pending_sign_ids = {tx2}`, count=1

At step 5, Alice holds tx1 + rbf1 in PendingVerify and tx2 in PendingSign — three concurrent active obligations against a limit of 1.

### Citations

**File:** contracts/satoshi-bridge/src/account.rs (L99-101)
```rust
    pub fn pending_sign_count(&self) -> u32 {
        u32::try_from(self.btc_pending_sign_ids.len()).unwrap_or(u32::MAX)
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

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L80-85)
```rust
        let max_pending = self.get_max_pending_sign_txs(&sender_id);
        let account = self.internal_unwrap_or_create_mut_account(&sender_id);
        require!(
            account.pending_sign_count() < max_pending,
            "Too many pending sign transactions"
        );
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

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L142-152)
```rust
    pub fn get_original_tx_id(&self) -> Option<&String> {
        match self.state.borrow() {
            PendingInfoState::WithdrawUserRbf(state) => Some(state.original_tx_id.borrow()),
            PendingInfoState::WithdrawCancelRbf(state) => Some(state.original_tx_id.borrow()),
            PendingInfoState::ActiveUtxoManagementRbf(state) => Some(state.original_tx_id.borrow()),
            PendingInfoState::ActiveUtxoManagementCancelRbf(state) => {
                Some(state.original_tx_id.borrow())
            }
            _ => None,
        }
    }
```

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

**File:** contracts/satoshi-bridge/src/api/chain_signatures.rs (L19-43)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_btc_transaction(
        &mut self,
        btc_pending_sign_id: String,
        sign_index: usize,
        key_version: u32,
    ) -> PromiseOrValue<bool> {
        let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);
        btc_pending_info.assert_pending_sign();
        if let Some(original_tx_id) = btc_pending_info.get_original_tx_id() {
            if !self.check_btc_pending_info_exists(original_tx_id) {
                require!(
                    self.internal_unwrap_mut_account(&btc_pending_info.account_id.clone())
                        .btc_pending_sign_ids
                        .remove(&btc_pending_sign_id),
                    "Internal error"
                );
                self.internal_remove_btc_pending_info(&btc_pending_sign_id);
                return PromiseOrValue::Value(true);
            }
        }
        self.internal_sign_btc_transaction(btc_pending_sign_id, sign_index, key_version)
            .into()
    }
```

**File:** contracts/satoshi-bridge/src/bitcoin_utils/contract_methods.rs (L34-36)
```rust
            self.internal_unwrap_mut_account(&account_id)
                .btc_pending_sign_ids
                .insert(btc_pending_id.clone());
```

**File:** contracts/satoshi-bridge/src/rbf/withdraw.rs (L43-48)
```rust
        require!(
            &original_tx_btc_pending_info.account_id == account_id,
            "Not allow"
        );
        original_tx_btc_pending_info.assert_not_canceled();
        original_tx_btc_pending_info.assert_withdraw_original_pending_verify_tx();
```
