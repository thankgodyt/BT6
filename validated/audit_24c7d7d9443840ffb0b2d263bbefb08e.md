### Title
Unbounded Account Iteration in `migrate_to_new_token_mint` Enables Permanent DoS of Token Migration - (File: `contracts/satoshi-bridge/src/nbtc/migration.rs`)

### Summary
The `migrate_to_new_token_mint` callback iterates over every nBTC holder to verify balances and mint on the new token contract. Gas consumption scales linearly with holder count. With NEAR's 300 Tgas transaction cap, the migration fails with as few as ~32 holders. Because any user can become an nBTC holder by depositing BTC — a fully unprivileged action — the migration can be permanently blocked by ordinary bridge usage or deliberate holder-set inflation.

### Finding Description
`internal_migrate_to_new_token` constructs N+1 parallel cross-contract queries (one `ft_total_supply` plus N `ft_balance_of` calls), each allocated `GAS_FOR_FT_QUERY = 3 Tgas`, then schedules a callback with statically computed gas:

```
callback_gas = GAS_FOR_MIGRATION_MINT_CALL_BACK (30 Tgas)
             + GAS_FOR_MIGRATION_RESOLVE_CALL_BACK (10 Tgas)
             + GAS_FOR_MINT_ACTION (5 Tgas) × N
``` [1](#0-0) 

Total gas consumed by the transaction: `3(N+1) + 40 + 5N = 8N + 43 Tgas`.

At NEAR's 300 Tgas hard cap: `N_max = (300 − 43) / 8 ≈ 32 accounts`.

The callback then enforces a strict invariant:

```rust
require!(
    sum == total_supply,
    "Sum of account balances does not match total supply"
);
``` [2](#0-1) 

This forces the `MigrationOperator` to supply **all** token holders in a single call. There is no batching mechanism. If the holder count exceeds ~32, the transaction exceeds the gas limit and the migration is permanently blocked — the operator cannot split the work because a partial list will always fail the `sum == total_supply` check.

### Impact Explanation
Token migration is permanently blocked once the nBTC holder count exceeds ~32. The bridge team cannot upgrade the token contract without deploying an entirely new bridge version. If the old token has a critical vulnerability requiring migration, the bridge is stuck in a state requiring operator intervention. This matches the **Medium** impact: *"stuck bridge state requiring operator intervention."*

### Likelihood Explanation
32 nBTC holders is a trivially low threshold reached through normal bridge usage. An attacker can also deliberately inflate the holder set by depositing BTC to multiple addresses — each deposit is a standard, unprivileged bridge operation. The cost is only BTC transaction fees, which is negligible relative to the impact of permanently blocking migration.

### Recommendation
Implement a batched migration mechanism. Replace the single-transaction `sum == total_supply` check with a multi-step flow: accumulate migrated balances across multiple calls and finalize only when the running total equals the total supply. This eliminates the gas ceiling on the number of holders that can be migrated.

### Proof of Concept
1. 33 users deposit BTC to receive nBTC, creating 33 nBTC holders (normal bridge usage).
2. Bridge team calls `migrate_to_new_token` with all 33 accounts.
3. Total gas: `8 × 33 + 43 = 307 Tgas` > 300 Tgas limit → transaction fails.
4. Supplying fewer accounts fails the `sum == total_supply` check.
5. Migration is permanently blocked with no on-chain remedy. [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** contracts/satoshi-bridge/src/nbtc/migration.rs (L6-9)
```rust
pub const GAS_FOR_FT_QUERY: Gas = Gas::from_tgas(3);
pub const GAS_FOR_MINT_ACTION: Gas = Gas::from_tgas(5);
pub const GAS_FOR_MIGRATION_MINT_CALL_BACK: Gas = Gas::from_tgas(30);
pub const GAS_FOR_MIGRATION_RESOLVE_CALL_BACK: Gas = Gas::from_tgas(10);
```

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

**File:** contracts/satoshi-bridge/src/nbtc/migration.rs (L71-81)
```rust
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
```
