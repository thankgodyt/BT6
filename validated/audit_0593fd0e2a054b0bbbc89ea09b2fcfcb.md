### Title
Token Migration Balance Snapshot Race Allows Pending Withdrawals to Permanently Brick — (`contracts/satoshi-bridge/src/nbtc/migration.rs`)

### Summary
`migrate_to_new_token` snapshots the old token's balances in one NEAR block and mints the equivalent on the new token in a later block. Any `ft_transfer_call` withdrawal initiated by a user between those two blocks deposits tokens into the bridge's old-token balance **after** the snapshot, so those tokens are never minted on the new token. After `nbtc_account_id` is flipped to the new token, `verify_withdraw` calls `burn()` on the new token against a bridge balance that is short by exactly the race-window withdrawal amount, causing the burn to fail and the user's withdrawal to be permanently stuck.

---

### Finding Description

`internal_migrate_to_new_token` fires parallel cross-contract view calls (`ft_total_supply` + `ft_balance_of` for every account in `accounts`) and chains them to `migrate_to_new_token_mint` as a callback. [1](#0-0) 

In `migrate_to_new_token_mint` the captured balances are summed and checked against the captured total supply: [2](#0-1) 

Both `total_supply` and each `balance` are read at the same NEAR block, so the invariant `sum == total_supply` holds at snapshot time. However, NEAR cross-contract calls are **not atomic**: other transactions execute between the snapshot block and the callback block.

The normal withdrawal flow is:

1. User calls `ft_transfer_call(bridge, amount, withdraw_msg)` on the old nbtc token.
2. The nbtc contract calls `ft_on_transfer` on the bridge; the bridge records a `BtcPendingInfo` and returns `0` (keeps all tokens). Bridge's old-token balance increases by `amount`.
3. Later, a relayer calls `verify_withdraw`, which calls `burn(burn_amount)` on `config.nbtc_account_id`. [3](#0-2) 

If a user executes step 1 **after** the migration snapshot but **before** `migrate_to_new_token_mint` runs:

- `total_supply` is unchanged (a transfer does not change supply).
- The bridge's captured balance is `X` (pre-transfer); the user's captured balance is `Y` (pre-transfer). `X + Y == total_supply` still holds — the check passes.
- The migration mints only `X` to the bridge on the new token.
- `migrate_to_new_token_resolve` sets `nbtc_account_id = new_token`. [4](#0-3) 

Now the bridge's new-token balance is `X`, but it must burn `burn_amount` (≤ `amount`) for the pending withdrawal. If `X < burn_amount`, the `burn` call panics and the withdrawal is permanently stuck. Even if `X >= burn_amount`, the bridge's protocol-fee reserve is silently consumed to cover the shortfall, because the `amount` tokens the user transferred are stranded in the bridge's **old**-token balance, which the bridge can no longer reach.

The migration function itself carries `#[pause(except(roles(Role::DAO)))]` but does **not** enforce that the bridge is paused before the snapshot, so the race window is open during every live migration. [5](#0-4) 

---

### Impact Explanation

A user whose withdrawal lands in the race window loses access to their nBTC (stuck in the bridge's old-token balance) and their BTC withdrawal cannot complete because the new-token burn fails. This is a **stuck bridge state requiring operator intervention** (the operator must manually reconcile balances or re-mint on the new token). In the worst case the user's funds are permanently locked with no on-chain recovery path.

---

### Likelihood Explanation

The migration is a real operational event (the codebase has a full `MigrationOperator` role and test suite for it). The race window spans at least one NEAR block between the view-call batch and the callback. Any user who happens to initiate a withdrawal during that window triggers the bug without any special knowledge or coordination. Likelihood is **low-medium** (requires coincident timing, but no attacker action is needed — ordinary user behaviour suffices).

---

### Recommendation

Before firing the balance-snapshot queries, atomically pause the bridge (or require it to already be paused) so that no new `ft_on_transfer` withdrawals can be accepted during the migration window. Alternatively, re-query the bridge's own balance inside `migrate_to_new_token_mint` (after the snapshot results arrive) and mint the **actual** current balance rather than the stale snapshot value, then verify `sum_of_user_balances + actual_bridge_balance == total_supply`.

---

### Proof of Concept

1. Operator calls `migrate_to_new_token(new_token, [alice, bob, ...])` on the bridge. The bridge fires `ft_total_supply` + `ft_balance_of` queries against the old token. Snapshot: `bridge_balance = 50_000`, `total_supply = 150_000`.

2. In the next NEAR block (before the callback), Alice calls `ft_transfer_call(bridge, 100_000, withdraw_msg)` on the old nbtc token. Bridge's old-token balance becomes `150_000`; Alice's balance becomes `0`. Total supply is still `150_000`.

3. `migrate_to_new_token_mint` callback runs. `sum = 50_000 (bridge) + 100_000 (alice) = 150_000 == total_supply`. Check passes. The migration mints `50_000` to bridge and `100_000` to Alice on the new token.

4. `migrate_to_new_token_resolve` sets `nbtc_account_id = new_token`.

5. Relayer calls `verify_withdraw` for Alice's pending withdrawal (`burn_amount = 95_000` after fees). Bridge calls `burn(95_000)` on the new token. Bridge's new-token balance is `50_000 < 95_000` → **panic / burn fails**. Alice's withdrawal is permanently stuck; her `100_000` old-token nBTC sits unreachable in the bridge's old-token balance. [6](#0-5) [3](#0-2)

### Citations

**File:** contracts/satoshi-bridge/src/nbtc/migration.rs (L23-43)
```rust
        let mut queries = ext_nbtc::ext(old_token.clone())
            .with_static_gas(GAS_FOR_FT_QUERY)
            .ft_total_supply();
        for account in &accounts {
            queries = queries.and(
                ext_nbtc::ext(old_token.clone())
                    .with_static_gas(GAS_FOR_FT_QUERY)
                    .ft_balance_of(account.clone()),
            );
        }

        let callback_gas = Gas::from_gas(
            GAS_FOR_MIGRATION_MINT_CALL_BACK.as_gas()
                + GAS_FOR_MIGRATION_RESOLVE_CALL_BACK.as_gas()
                + GAS_FOR_MINT_ACTION.as_gas() * accounts.len() as u64,
        );
        queries.then(
            Self::ext(env::current_account_id())
                .with_static_gas(callback_gas)
                .migrate_to_new_token_mint(new_token, accounts),
        )
```

**File:** contracts/satoshi-bridge/src/nbtc/migration.rs (L58-109)
```rust
    pub fn migrate_to_new_token_mint(
        &mut self,
        new_token: AccountId,
        accounts: Vec<AccountId>,
    ) -> PromiseOrValue<()> {
        require!(
            env::promise_results_count() == accounts.len() as u64 + 1,
            "Unexpected number of promise results"
        );

        let total_supply = Self::parse_ft_result(0);
        let mut sum: u128 = 0;
        let mut entries: Vec<(AccountId, u128)> = Vec::new();
        for (index, account) in accounts.into_iter().enumerate() {
            let balance = Self::parse_ft_result(index as u64 + 1);
            sum += balance;
            if balance > 0 {
                entries.push((account, balance));
            }
        }
        require!(
            sum == total_supply,
            "Sum of account balances does not match total supply"
        );

        let accounts_count = entries.len();
        let mut mint_batch = Promise::new(new_token.clone());
        for (account, amount) in entries {
            let args = serde_json::to_vec(&json!({
                "mint_account_id": account,
                "mint_amount": U128(amount),
                "protocol_fee": U128(0),
                "relayer_account_id": env::current_account_id(),
                "relayer_fee": U128(0),
                "post_actions": null,
            }))
            .unwrap_or_else(|_| env::panic_str("Failed to serialize mint args"));
            mint_batch = mint_batch.function_call(
                "mint".to_string(),
                args,
                NearToken::from_yoctonear(0),
                GAS_FOR_MINT_ACTION,
            );
        }
        mint_batch
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_MIGRATION_RESOLVE_CALL_BACK)
                    .migrate_to_new_token_resolve(new_token, accounts_count, U128(total_supply)),
            )
            .into()
    }
```

**File:** contracts/satoshi-bridge/src/nbtc/migration.rs (L112-126)
```rust
    pub fn migrate_to_new_token_resolve(
        &mut self,
        new_token: AccountId,
        accounts: usize,
        total_amount: U128,
    ) {
        require!(is_promise_success(), "Migration mint failed");
        self.internal_mut_config().nbtc_account_id = new_token.clone();
        Event::TokenMigrated {
            new_token: &new_token,
            accounts,
            total_amount,
        }
        .emit();
    }
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L11-30)
```rust
    pub fn verify_withdraw_burn_promise(&self, tx_id: String) -> Promise {
        let btc_pending_info = self.internal_unwrap_btc_pending_info(&tx_id);
        let config = self.internal_config();
        let (protocol_fee, relayer_fee) = config
            .withdraw_bridge_fee
            .get_protocol_and_relayer_fee(btc_pending_info.withdraw_fee);
        ext_nbtc::ext(config.nbtc_account_id.clone())
            .with_static_gas(GAS_FOR_BURN_CALL)
            .burn(
                btc_pending_info.account_id.clone(),
                btc_pending_info.burn_amount.into(),
                env::signer_account_id(),
                relayer_fee.into(),
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_WITHDRAW_BURN_CALL_BACK)
                    .verify_withdraw_burn_callback(tx_id, protocol_fee.into(), relayer_fee.into()),
            )
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L189-199)
```rust
    #[payable]
    #[access_control_any(roles(Role::MigrationOperator, Role::DAO))]
    #[pause(except(roles(Role::DAO)))]
    pub fn migrate_to_new_token(
        &mut self,
        new_token: AccountId,
        accounts: Vec<AccountId>,
    ) -> Promise {
        assert_one_yocto();
        self.internal_migrate_to_new_token(new_token, accounts)
    }
```
