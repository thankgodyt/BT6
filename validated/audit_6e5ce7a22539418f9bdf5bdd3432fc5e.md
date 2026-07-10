### Title
Migration Permanently Griefable: Any nBTC Holder Can Continuously Block `migrate_to_new_token` by Splitting Balances to Unknown Accounts — (File: `contracts/satoshi-bridge/src/nbtc/migration.rs`)

---

### Summary

The bridge's token migration flow requires the `MigrationOperator` to supply a complete, exhaustive list of every nBTC-holding account. The callback enforces `sum(balances) == total_supply` before minting on the new contract. Because the nBTC contract has no on-chain account enumeration and no pause on `ft_transfer`, any unprivileged nBTC holder can race-transfer tokens to a fresh account not in the operator's list, causing the invariant check to fail and aborting migration. This can be repeated indefinitely.

---

### Finding Description

`internal_migrate_to_new_token` issues parallel `ft_balance_of` queries for every account in the caller-supplied `accounts` list, then in `migrate_to_new_token_mint` enforces:

```rust
require!(
    sum == total_supply,
    "Sum of account balances does not match total supply"
);
``` [1](#0-0) 

The `accounts` list is provided by the `MigrationOperator` at call time. The nBTC contract (`contracts/nbtc/src/lib.rs`) exposes standard NEP-141 `ft_transfer` and `ft_transfer_call` with no pause guard:

```rust
fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
    ...
    self.token.ft_transfer(receiver_id, amount, memo);
}
``` [2](#0-1) 

There is no `pause` mechanism on `ft_transfer` in the nBTC contract — `assert_bridge()` only guards `mint` and `burn`. [3](#0-2) 

**Attack path:**

1. Attacker holds any amount of nBTC (acquired legitimately by depositing BTC or buying on secondary market).
2. Operator assembles a complete `accounts` list off-chain (NEAR has no on-chain token-holder enumeration) and submits `migrate_to_new_token(new_token, accounts)`.
3. Before or concurrently with the operator's transaction, the attacker calls `storage_deposit` on the nBTC contract to register a fresh account, then calls `ft_transfer` to move even 1 satoshi of nBTC to that account.
4. The fresh account is not in the operator's `accounts` list, so `sum(balances) < total_supply`.
5. `migrate_to_new_token_mint` panics: `"Sum of account balances does not match total supply"`.
6. The attacker repeats step 3 with a new account each time the operator retries.

The attacker only needs to hold a non-zero nBTC balance and can split it across arbitrarily many accounts to sustain the attack indefinitely. [4](#0-3) 

---

### Impact Explanation

Migration to a new nBTC token contract is indefinitely blocked. Any critical upgrade (security patch, new token logic) that depends on `migrate_to_new_token` completing cannot proceed while the attacker sustains the griefing. The bridge remains stuck on the old token contract. This maps to: **Medium — attacker-triggered temporary locking of bridge migration state requiring operator intervention.** [5](#0-4) 

---

### Likelihood Explanation

Any nBTC holder — including any user who has ever deposited BTC into the bridge — can execute this attack. No privileged access is required. The cost is only the NEAR storage deposit for registering new accounts (~0.00125 NEAR each) plus the gas for transfers. The attacker does not lose their nBTC principal. Likelihood is **Medium-High**. [6](#0-5) 

---

### Recommendation

1. **Pause `ft_transfer` before migration**: Add a pausability guard (via `near-plugins` `Pausable`) to the nBTC contract's `ft_transfer` and `ft_transfer_call` methods, and require the operator to pause transfers before initiating migration. This closes the race window.

2. **Alternatively, remove the strict equality check**: Instead of requiring `sum == total_supply`, allow migration to proceed if `sum <= total_supply` and treat any unaccounted remainder as belonging to a known protocol-controlled account (e.g., `bridge_id`), or allow the operator to supply a "remainder" account.

3. **On-chain account registry**: Maintain an enumerable set of registered accounts in the nBTC contract so the operator can retrieve the complete list atomically on-chain rather than relying on off-chain event tracking. [7](#0-6) 

---

### Proof of Concept

```
// Setup: attacker holds 1000 nBTC satoshis in account "attacker.near"

// Step 1: Operator assembles accounts list = ["alice.near", "bob.near", "attacker.near"]
// Step 2: Operator submits migrate_to_new_token(new_token, ["alice.near", "bob.near", "attacker.near"])

// Step 3: Attacker (racing the operator's tx) calls:
//   nbtc.storage_deposit(account_id: "fresh1.near", registration_only: false)
//   nbtc.ft_transfer(receiver_id: "fresh1.near", amount: "1", memo: null)

// Step 4: migrate_to_new_token_mint callback fires:
//   total_supply = 1000
//   sum = balance("alice") + balance("bob") + balance("attacker") = 999  // attacker now has 999
//   999 != 1000 → panic("Sum of account balances does not match total supply")

// Step 5: Operator retries with ["alice.near", "bob.near", "attacker.near", "fresh1.near"]
// Step 6: Attacker transfers 1 satoshi to "fresh2.near" → repeat indefinitely
``` [8](#0-7)

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

**File:** contracts/satoshi-bridge/src/nbtc/migration.rs (L58-81)
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

**File:** contracts/nbtc/src/lib.rs (L183-196)
```rust
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        // Legacy bridging flow used by Near Intents
        if receiver_id == env::current_account_id()
            && memo
                .as_ref()
                .is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
        {
            if let Some(withdraw_relayer) = Self::read_withdraw_relayer_address() {
                return self.token.ft_transfer(withdraw_relayer, amount, memo);
            }
        }

        self.token.ft_transfer(receiver_id, amount, memo);
    }
```

**File:** contracts/nbtc/src/lib.rs (L238-246)
```rust
impl StorageManagement for Contract {
    #[payable]
    fn storage_deposit(
        &mut self,
        account_id: Option<AccountId>,
        registration_only: Option<bool>,
    ) -> StorageBalance {
        self.token.storage_deposit(account_id, registration_only)
    }
```

**File:** contracts/nbtc/src/lib.rs (L332-334)
```rust
    fn assert_bridge(&self) {
        require!(self.bridge_id == env::predecessor_account_id(), "Not Allow");
    }
```
