### Title
Single Mint Failure in Sequential Batch Permanently Blocks Token Migration - (`contracts/satoshi-bridge/src/nbtc/migration.rs`)

### Summary

`migrate_to_new_token_mint` chains all per-account `mint` calls into a single sequential NEAR batch. If any one mint fails, the entire batch reverts and `migrate_to_new_token_resolve` panics with "Migration mint failed", leaving the config unchanged. Because `sum == total_supply` forces every token holder to be included, the migration can never succeed as long as any single account's mint is persistently rejected by the new token contract.

### Finding Description

`internal_migrate_to_new_token` first queries `ft_total_supply` and `ft_balance_of` for every supplied account, then passes control to `migrate_to_new_token_mint`. [1](#0-0) 

Inside `migrate_to_new_token_mint`, after verifying `sum == total_supply`, all non-zero-balance accounts are minted on the new token by chaining `.function_call()` calls into a single batch: [2](#0-1) 

Each call is allocated only `GAS_FOR_MINT_ACTION = 5 TGas`. [3](#0-2) 

In NEAR, a batch of `.function_call()` actions is atomic: if any action fails, the entire batch fails. The resolve callback then unconditionally panics: [4](#0-3) 

Because `nbtc_account_id` is only updated on success, the bridge remains on the old token. There is no partial-migration path and no way to exclude a single problematic account, since the `sum == total_supply` invariant requires every holder to be present. [5](#0-4) 

### Impact Explanation

If any account's mint on the new token contract persistently fails — for example because the new token enforces different storage-registration requirements, has a per-account allowlist, or the 5 TGas budget is insufficient for a more complex `mint` implementation — the migration is permanently blocked. The bridge operator cannot exclude the offending account without first burning or transferring its balance on the old token through a separate privileged action. This is a stuck bridge state requiring operator intervention, matching the Medium impact tier.

### Likelihood Explanation

The `migrate_to_new_token` entry point is restricted to `MigrationOperator` or `DAO`. [6](#0-5) 

However, any unprivileged nBTC holder can indirectly cause the failure: if their account is not registered on the new token contract (a common NEP-141 requirement) and the new token's `mint` panics rather than returning an error, the migration will always revert. The mint calls attach zero NEAR, so any new-token implementation that charges storage deposit will fail for unregistered accounts. [7](#0-6) 

### Recommendation

1. **Iterate with individual callbacks instead of a single batch.** Issue one `mint` per callback round-trip so a failure on one account can be logged and skipped without reverting the others.
2. **Allow partial migration.** Track which accounts have been successfully minted (e.g., in a `LookupSet`) and allow the operator to call `migrate_to_new_token` in multiple batches, relaxing the `sum == total_supply` check to `sum_so_far + remaining_supply == total_supply`.
3. **Increase per-mint gas budget.** `GAS_FOR_MINT_ACTION = 5 TGas` is very tight; a new token with storage-registration logic will exceed it.
4. **Pre-validate accounts.** Before building the mint batch, verify that each account is registered on the new token and attach sufficient NEAR for storage if needed.

### Proof of Concept

1. Alice holds 1 satoshi of nBTC on the old token.
2. The new token contract requires `storage_deposit` before `mint` can succeed for a new account; Alice has not registered.
3. `MigrationOperator` calls `migrate_to_new_token(new_token, [alice, bob, charlie, ...])`.
4. `migrate_to_new_token_mint` builds a batch: `mint(alice, 1)`, `mint(bob, X)`, …
5. `mint(alice, 1)` panics inside the new token (no storage) → entire batch reverts.
6. `migrate_to_new_token_resolve` receives `is_promise_success() == false` → panics "Migration mint failed".
7. `nbtc_account_id` is unchanged. Every subsequent retry produces the same result. The bridge is permanently unable to migrate its token contract.

### Citations

**File:** contracts/satoshi-bridge/src/nbtc/migration.rs (L7-7)
```rust
pub const GAS_FOR_MINT_ACTION: Gas = Gas::from_tgas(5);
```

**File:** contracts/satoshi-bridge/src/nbtc/migration.rs (L12-44)
```rust
    pub(crate) fn internal_migrate_to_new_token(
        &mut self,
        new_token: AccountId,
        accounts: Vec<AccountId>,
    ) -> Promise {
        let old_token = self.internal_config().nbtc_account_id.clone();
        require!(
            new_token != old_token,
            "New token must differ from the current token"
        );

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
    }
```

**File:** contracts/satoshi-bridge/src/nbtc/migration.rs (L78-108)
```rust
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
