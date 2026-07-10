### Title
Token Minting Not Synchronized with Migration Snapshot Causes Permanent Loss of User Funds - (File: `contracts/satoshi-bridge/src/nbtc/migration.rs`)

---

### Summary

The `migrate_to_new_token` flow in `satoshi-bridge` takes an asynchronous snapshot of the old token's supply and balances, then mints equivalent amounts on the new token. There is no mechanism to halt minting on the old token during the multi-block async window. Any tokens minted on the old token **after the snapshot is taken but before `migrate_to_new_token_resolve` updates `nbtc_account_id`** are permanently stranded on the old token and never migrated, causing permanent loss of user funds.

---

### Finding Description

**Step 1 — Snapshot initiation (`internal_migrate_to_new_token`):**

`internal_migrate_to_new_token` sends a batch of cross-contract queries to the old token: one `ft_total_supply` call and one `ft_balance_of` per account. [1](#0-0) 

These queries execute atomically against the old token's state at the block they land in. The callback `migrate_to_new_token_mint` executes in a **later block**, after the async cross-contract round-trip.

**Step 2 — The unsynchronized window:**

During the async gap between the snapshot queries and the callback, `config.nbtc_account_id` still points to the **old token**. The bridge is not paused and no migration lock exists. A whitelisted relayer can submit a valid deposit proof, which the bridge verifies and then calls `mint` on the old token — increasing its `total_supply` beyond the snapshot value.

**Step 3 — Integrity check passes on stale data (`migrate_to_new_token_mint`):**

The callback reads `total_supply` from `promise_result_checked(0, ...)` — the snapshot result — and sums the snapshot balances: [2](#0-1) 

Both `total_supply` and `sum` are from the **same snapshot point in time**, so `sum == total_supply` holds even though the old token's live supply has since increased. The check does not re-query the current supply. Accounts with `balance == 0` at snapshot time (including newly minted accounts) are excluded from migration: [3](#0-2) 

**Step 4 — New token minted with stale amount; config updated:**

The new token receives only the snapshot amount. `migrate_to_new_token_resolve` then permanently updates `nbtc_account_id` to the new token: [4](#0-3) 

Any tokens minted on the old token during the window are now permanently stranded. The bridge no longer accepts the old token for withdrawals.

---

### Impact Explanation

**Critical — Permanent loss of user funds.**

A user whose deposit was processed during the migration window:
- Has their BTC permanently locked in the bridge (the bridge holds the UTXO).
- Holds nBTC on the **old** token contract, which the bridge no longer recognizes.
- Cannot initiate a withdrawal (bridge uses new token for burn verification).
- Cannot receive equivalent new tokens (they were not in the migration snapshot).

The BTC is irretrievably locked and the user's nBTC is worthless.

---

### Likelihood Explanation

- Token migration is a planned, infrequent operation, but it spans **multiple NEAR blocks** (several seconds) due to async cross-contract calls.
- Whitelisted relayers operate continuously and submit deposit proofs as they arrive from the Bitcoin network. There is no coordination mechanism between relayers and the migration operator.
- No code requires the bridge to be paused before calling `migrate_to_new_token`.
- The `Pausable` trait exists on the contract but is not enforced as a precondition of migration. [5](#0-4) 

The race is realistic in any production environment where relayers and operators act independently.

---

### Recommendation

1. **Require the bridge to be paused** before `migrate_to_new_token` can be called. Add `self.assert_not_paused()` or an equivalent guard at the entry point of `internal_migrate_to_new_token`.
2. **Re-verify supply in the callback**: In `migrate_to_new_token_mint`, re-query the old token's live `ft_total_supply` and compare it against the snapshot `total_supply`. If they differ, abort the migration.
3. **Emit a migration-in-progress flag** in bridge state at initiation time and reject new mints while it is set, analogous to the `mintingFinished` check recommended in the original report.

---

### Proof of Concept

1. MigrationOperator calls `migrate_to_new_token(new_token, [alice, bob, ...])` with all current holders.
2. Bridge sends snapshot queries to old token: `ft_total_supply` → 100, `ft_balance_of(alice)` → 60, `ft_balance_of(bob)` → 40.
3. **In the next NEAR block**, a relayer submits a valid BTC deposit proof for Carol (10 BTC). Bridge verifies the proof and calls `mint` on the old token → Carol receives 10 nBTC; old token `total_supply` = 110.
4. `migrate_to_new_token_mint` callback executes: `total_supply` (snapshot) = 100, `sum` (snapshot) = 100 → `require!(sum == total_supply)` **passes**.
5. Carol's balance at snapshot time was 0, so she is excluded from `entries` (line 74 check). New token is minted: alice=60, bob=40 (total 100).
6. `migrate_to_new_token_resolve` sets `config.nbtc_account_id = new_token`.
7. Carol holds 10 nBTC on the **old** token. The bridge uses the new token. Carol's 10 BTC is permanently locked. Her old nBTC cannot be used to withdraw. [6](#0-5)

### Citations

**File:** contracts/satoshi-bridge/src/nbtc/migration.rs (L23-32)
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

**File:** contracts/satoshi-bridge/src/nbtc/migration.rs (L118-119)
```rust
        require!(is_promise_success(), "Migration mint failed");
        self.internal_mut_config().nbtc_account_id = new_token.clone();
```

**File:** contracts/satoshi-bridge/src/lib.rs (L160-163)
```rust
#[near(contract_state)]
#[derive(Pausable, Upgradable, PanicOnDefault)]
#[access_control(role_type(Role))]
#[pausable(pause_roles(Role::PauseManager), unpause_roles(Role::UnpauseManager))]
```
