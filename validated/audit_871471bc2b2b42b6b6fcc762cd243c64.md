### Title
Operator `cancel_withdraw` Blocked by User Front-Running Pending-Sign Capacity Check — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

### Summary

The privileged `cancel_withdraw` function calls `require_pending_sign_capacity` against the **user's** account before creating the RBF cancel transaction. Because the default per-account pending-sign limit is 1, a user who already holds one pending-sign entry causes the operator's call to panic. A user can deliberately front-run any `cancel_withdraw` targeting their account by submitting a new withdrawal, permanently blocking the operator from cancelling their in-flight withdrawal.

### Finding Description

`cancel_withdraw` is restricted to `Role::DAO` or `Role::Operator` and is the mechanism by which the protocol forcibly cancels a user's unconfirmed withdrawal via RBF. [1](#0-0) 

Before constructing the cancel RBF transaction it calls:

```rust
let user_account_id = self
    .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
    .account_id
    .clone();
self.require_pending_sign_capacity(&user_account_id);
``` [2](#0-1) 

`require_pending_sign_capacity` panics if the account's `btc_pending_sign_ids` count is not strictly less than the configured limit: [3](#0-2) 

The default limit is **1**: [4](#0-3) 

A normal withdrawal moves from `btc_pending_sign_ids` to `btc_pending_verify_list` once signing completes, so when the operator calls `cancel_withdraw` the user's sign-slot is typically free. However, the user can observe the operator's intent and immediately submit a new `ft_transfer_call` → `ft_on_transfer` withdrawal, which inserts a new entry into `btc_pending_sign_ids`. When the operator's transaction is then processed, `pending_sign_count() = 1`, the check `1 < 1` is `false`, and the call panics with `"Too many pending sign transactions"`.

The user can repeat this indefinitely: each time the operator retries, the user front-runs with another withdrawal (or an `execute_refund` call, which also calls `require_pending_sign_capacity` and inserts into `btc_pending_sign_ids`): [5](#0-4) 

### Impact Explanation

The operator loses the ability to cancel a targeted user's withdrawal. The original unconfirmed Bitcoin transaction remains in the mempool indefinitely. If the transaction is stuck (e.g., fee too low), the bridge cannot reclaim the UTXOs or redirect funds, resulting in a stuck bridge state that requires operator intervention with no available on-chain remedy. This matches the **Medium** impact category: *attacker-triggered temporary locking of bridged funds / stuck bridge state requiring operator intervention*.

### Likelihood Explanation

NEAR transactions within a shard are ordered, but a user monitoring the mempool or the operator's announced intent can submit a new withdrawal in the same or a preceding block. The attack requires only that the user hold a small amount of nBTC (enough to initiate a minimal withdrawal) and a bot watching for `cancel_withdraw` calls targeting their account. The default pending-sign limit of 1 makes the threshold trivially easy to hit.

### Recommendation

Remove the `require_pending_sign_capacity` check on the **user's** account from `cancel_withdraw` (and the analogous `cancel_active_utxo_management`). The capacity guard exists to prevent users from flooding the signing pipeline with their own requests; it should not gate a privileged operator action that creates a cancel transaction on the user's behalf. If a slot limit is still needed for the cancel RBF, use a separate, operator-controlled counter or simply allow the cancel transaction to exceed the normal per-user limit.

### Proof of Concept

1. User Alice initiates a withdrawal: `ft_transfer_call(bridge, amount, msg)` → `ft_on_transfer` → `internal_sign_btc_transaction`. Alice's `btc_pending_sign_ids` = `{tx_A}`.
2. MPC signing completes; `tx_A` moves to `btc_pending_verify_list`. Alice's `btc_pending_sign_ids` = `{}`.
3. Operator decides to cancel Alice's withdrawal and submits `cancel_withdraw(tx_A, output)`.
4. Alice's bot detects the pending operator call and immediately submits a new `ft_transfer_call` withdrawal. Alice's `btc_pending_sign_ids` = `{tx_B}`.
5. Operator's `cancel_withdraw` executes: `require_pending_sign_capacity(&alice)` evaluates `1 < 1` → `false` → panics with `"Too many pending sign transactions"`.
6. Alice repeats step 4 on every retry. The operator can never cancel Alice's withdrawal. [1](#0-0) [3](#0-2)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L283-299)
```rust
    #[access_control_any(roles(Role::DAO, Role::Operator))]
    #[pause(except(roles(Role::DAO)))]
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

**File:** contracts/satoshi-bridge/src/refund.rs (L339-342)
```rust
        if !self.check_account_exists(&caller) {
            self.internal_set_account(&caller, crate::Account::new(&caller));
        }
        self.require_pending_sign_capacity(&caller);
```
