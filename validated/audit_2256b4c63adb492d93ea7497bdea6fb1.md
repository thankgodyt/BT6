### Title
In-flight Deposit During `migrate_to_new_token` Causes User to Receive Worthless Old nBTC, Permanently Losing BTC Value - (File: contracts/satoshi-bridge/src/nbtc/migration.rs)

### Summary
When `migrate_to_new_token` completes while a standard deposit's async promise chain is mid-flight — specifically after `verify_deposit_callback` has already dispatched `mint` to the **old** token but before `mint_callback` executes — the deposit finalises on the old token after `config.nbtc_account_id` has been updated to the new token. The user receives old nBTC that the bridge no longer recognises for withdrawals, permanently losing their deposited BTC value.

### Finding Description
The deposit flow is a multi-step async promise chain across several NEAR blocks:

1. `verify_deposit_callback` inserts the UTXO into `verified_deposit_utxo` and dispatches `ext_nbtc::ext(self.internal_config().nbtc_account_id.clone()).mint(...)` — capturing the **current** `nbtc_account_id` (old token) at dispatch time. [1](#0-0) 

2. `mint_callback` runs in a later block. On success it calls `internal_set_utxo`, adding the UTXO to the bridge's spendable pool and crediting the user with old nBTC. [2](#0-1) 

The migration flow is also async:

3. `migrate_to_new_token_mint` batches `mint` calls to the **new** token for every holder of the old token, using a balance snapshot taken at migration initiation. [3](#0-2) 

4. `migrate_to_new_token_resolve` atomically updates `config.nbtc_account_id` to the new token only after all new-token mints succeed. [4](#0-3) 

**Race window:** If the migration's balance snapshot (step 3) is taken while the deposit recipient's balance is still zero (deposit not yet finalised), and the migration resolves (step 4) before `mint_callback` runs (step 2), then:

- The `mint` call was already dispatched to the **old** token — it succeeds because the old token is still live and the bridge is still its `bridge_id`.
- `mint_callback` succeeds: the UTXO enters the bridge's spendable pool and the user receives old nBTC.
- `config.nbtc_account_id` now points to the new token.
- The user's old nBTC balance was **not** included in the migration snapshot, so no equivalent new nBTC was minted for them.

The bridge's withdrawal path calls `burn` on `config.nbtc_account_id` (new token). The user holds old nBTC, which the bridge no longer accepts. The user cannot withdraw their BTC. [5](#0-4) 

There is no recovery path: the UTXO is in `verified_deposit_utxo` (blocking refund), the bridge's available UTXO pool now contains the user's BTC (spendable by other withdrawals), and no contract mechanism exists to swap old nBTC for new nBTC.

### Impact Explanation
The depositing user permanently loses their BTC value. Their BTC enters the bridge's spendable UTXO pool and subsidises other users' withdrawals, while the user is left holding old nBTC tokens that cannot be redeemed through the bridge. This constitutes a significant, permanent loss of user funds matching the "Critical/Medium — permanent locking or loss of user funds" impact class.

### Likelihood Explanation
Low. The migration is a privileged `MigrationOperator`/`DAO` operation. However, the contract does not enforce pausing the bridge before migration, and the deposit promise chain spans multiple NEAR blocks, creating a realistic race window. A migration operator who does not explicitly pause the bridge first can inadvertently trigger this condition for any deposit in-flight at migration time. [6](#0-5) 

### Recommendation
Before executing `migrate_to_new_token`, the bridge should be paused (or the function should enforce it) to ensure no deposit promise chains are in-flight. Alternatively, `migrate_to_new_token_resolve` should verify that the sum of old-token balances still equals the snapshot total before committing the config update, and revert if a new deposit has appeared since the snapshot.

### Proof of Concept
1. User sends BTC to deposit address; relayer calls `verify_deposit`.
2. `verify_deposit_callback` runs: UTXO inserted into `verified_deposit_utxo`; `mint` dispatched to **old** nBTC token (recipient balance = 0 at this moment).
3. Migration operator calls `migrate_to_new_token([...all current holders...])`. The balance snapshot sees recipient balance = 0, so no new nBTC is minted for them. `migrate_to_new_token_resolve` sets `config.nbtc_account_id = new_token`.
4. `mint_callback` runs: old-token `mint` succeeded; UTXO added to bridge's available pool; user credited with old nBTC.
5. User calls `old_nbtc.ft_transfer_call(bridge, amount, withdraw_msg)`. Bridge receives old nBTC but later calls `new_nbtc.burn(bridge, amount, ...)` — bridge has zero new nBTC balance, burn fails, withdrawal reverts.
6. User's BTC is permanently inaccessible to them; old nBTC is unredeemable through the bridge.

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L369-384)
```rust
        require!(
            self.data_mut()
                .verified_deposit_utxo
                .insert(pending_utxo_info.utxo_storage_key.clone()),
            "Already deposit utxo"
        );
        self.internal_mint_promise(
            recipient_id,
            mint_amount,
            protocol_fee,
            relayer_fee,
            pending_utxo_info,
            post_actions,
        )
        .into()
    }
```

**File:** contracts/satoshi-bridge/src/nbtc/mint.rs (L54-68)
```rust
        let is_success = is_promise_success();
        if is_success {
            if !self.check_account_exists(&recipient_id) {
                self.internal_set_account(&recipient_id, Account::new(&recipient_id));
            }
            if protocol_fee.0 > 0 {
                self.data_mut().acc_collected_protocol_fee += protocol_fee.0;
                self.data_mut().cur_available_protocol_fee += protocol_fee.0;
            }
            Event::UtxoAdded {
                utxo_storage_keys: vec![pending_utxo_info.utxo_storage_key.clone()],
                balances: Some(vec![U128::from(u128::from(pending_utxo_info.utxo.balance))]),
            }
            .emit();
            self.internal_set_utxo(&pending_utxo_info.utxo_storage_key, pending_utxo_info.utxo);
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
