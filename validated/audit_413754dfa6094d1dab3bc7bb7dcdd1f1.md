### Title
Strict Equality Check in `migrate_to_new_token_mint` Allows Any nBTC Holder to Permanently DoS Token Migration - (File: `contracts/satoshi-bridge/src/nbtc/migration.rs`)

### Summary

The `migrate_to_new_token_mint` callback enforces a strict equality `sum == total_supply` to verify that all token holders were enumerated. Because nBTC transfers are not paused during migration, any token holder can front-run the migration by transferring tokens to an account that was not included in the `accounts` list, causing the equality check to fail and permanently reverting the migration.

### Finding Description

`internal_migrate_to_new_token` issues a batch of cross-contract queries — one `ft_total_supply()` and one `ft_balance_of(account)` per listed account — then chains the callback `migrate_to_new_token_mint`. [1](#0-0) 

Inside the callback, the contract sums the queried balances and enforces:

```rust
require!(
    sum == total_supply,
    "Sum of account balances does not match total supply"
);
``` [2](#0-1) 

The `total_supply` and per-account balances are snapshot values from the query block. The callback executes in a later block. Any nBTC `ft_transfer` that moves tokens **to an account not in `accounts`** between the query block and the callback block causes `sum < total_supply`, making the equality fail and reverting the entire migration.

The attack requires no privileged access: any account that holds nBTC can call `ft_transfer` on the nBTC contract to send even 1 satoshi to a fresh account. Because NEAR cross-contract calls are asynchronous (queries fire in block N, callback lands in block N+k), the window is always open. An attacker can also act before the migration is submitted: if they hold tokens in any account the DAO did not enumerate, the check fails immediately.

### Impact Explanation

The token migration is the bridge's upgrade path for the nBTC token contract. A successful DoS means:

- The bridge is permanently stuck on the old token contract.
- If the migration is being performed to escape a vulnerability in the current nBTC contract, the DoS directly prevents the security fix from taking effect.
- The DAO cannot complete migration as long as the attacker keeps transferring tokens to unlisted accounts — a trivially repeatable action costing only gas.

This matches the allowed impact: **bypass of bridge migration controls with real security impact** (Critical) or at minimum **stuck bridge state requiring operator intervention** (Medium).

### Likelihood Explanation

- Any nBTC holder can execute the attack with a single `ft_transfer` call.
- No privileged access, leaked keys, or external dependency compromise is required.
- The attack is repeatable at negligible cost (one transfer per migration attempt).
- The NEAR async execution model guarantees the window always exists between query and callback.

### Recommendation

Replace the strict equality with a `>=` check, or restructure the check to tolerate unlisted holders:

```diff
- require!(
-     sum == total_supply,
-     "Sum of account balances does not match total supply"
- );
+ require!(
+     sum <= total_supply,
+     "Sum of account balances exceeds total supply"
+ );
```

Additionally, consider pausing nBTC transfers (if a pause mechanism exists) for the duration of the migration, or using a snapshot-based approach that reads balances atomically within a single contract call rather than via async cross-contract queries.

### Proof of Concept

1. DAO calls `migrate_to_new_token(new_token, [alice, bob, charlie])` — a list of all known holders.
2. The bridge fires cross-contract queries: `ft_total_supply()` → 1,000,000 sat; `ft_balance_of(alice)` → 500,000; `ft_balance_of(bob)` → 300,000; `ft_balance_of(charlie)` → 200,000.
3. Before the callback lands, attacker (alice) calls `ft_transfer(dave, 1)` on the nBTC contract, moving 1 sat to `dave` (not in the list).
4. `migrate_to_new_token_mint` callback fires: `total_supply = 1,000,000`; `sum = 499,999 + 300,000 + 200,000 = 999,999`.
5. `require!(999,999 == 1,000,000)` → panics with `"Sum of account balances does not match total supply"`.
6. Migration reverts. Attacker repeats step 3 on every subsequent attempt. [3](#0-2)

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
