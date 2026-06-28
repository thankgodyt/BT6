### Title
`StorageBalance.total` Not Updated When Message-Account Balance Is Transferred — (`File: near/omni-bridge/src/storage.rs`)

### Summary

`try_to_transfer_balance_from_message_account` credits the message account's NEAR balance to the storage payer's `available` field but never updates the storage payer's `total` field. This creates a persistent disparity between `total` and `available` — the exact analog of the reported `total_amount` / `balance_amount` inconsistency — that permanently prevents the storage payer from withdrawing the credited NEAR through the normal `storage_withdraw` path.

### Finding Description

`StorageBalance` has two invariant-paired fields that are always updated together throughout the contract:

- `total` — total NEAR ever deposited for this account (analogous to `total_amount`)
- `available` — NEAR currently free to spend (analogous to `balance_amount`)

In `storage_deposit`, both fields are incremented together: [1](#0-0) 

In `storage_withdraw`, both fields are decremented together: [2](#0-1) 

However, in `try_to_transfer_balance_from_message_account`, only `available` is increased — `total` is left unchanged: [3](#0-2) 

After this call, the storage payer's state is:
- `available = (original_available) + balance.total`
- `total` = unchanged (original value)

This means `available` can exceed `total`, breaking the invariant that `total - available == storage_used`.

### Impact Explanation

**`storage_withdraw` is blocked.** The function uses `checked_sub` on `total`: [4](#0-3) 

When `amount` is `None`, `to_withdraw = available`. If `available > total`, `total.checked_sub(available)` underflows and panics. Even with an explicit amount, the user can only withdraw up to `total`, not the full `available` — the difference (equal to the message account's `balance.total`) is permanently inaccessible via this path.

**`storage_unregister` without `force` is blocked.** The guard checks: [5](#0-4) 

With `available > total - min_required`, `total.saturating_sub(available)` underflows to 0, which is not equal to `min_required`, so the check always fails.

**`storage_unregister` with `force = true` is the only escape**, but it removes the account from `accounts_balances`. Any subsequent storage refund from removing a pending transfer silently drops because `accounts_balances.get(&transfer.owner)` returns `None`: [6](#0-5) 

The net result: NEAR deposited as a native fee to the message account is credited to `available` but is unwithdrawable via `storage_withdraw`, and recovering it via `storage_unregister(force=true)` forfeits all pending-transfer storage refunds.

### Likelihood Explanation

The vulnerable path is triggered by any unprivileged bridge user who initiates an outbound transfer with a non-zero `native_token_fee` and a pre-funded message account. This is the standard flow for native-fee-based transfers: [7](#0-6) 

It is also triggered in `init_transfer_resume` for the yield-based path: [8](#0-7) 

Any user who uses the native fee mechanism is affected. No special privileges are required.

### Recommendation

In `try_to_transfer_balance_from_message_account`, update both `total` and `available` together, mirroring the invariant maintained everywhere else in the contract:

```rust
storage.total = storage.total.saturating_add(balance.total);
storage.available = storage.available.saturating_add(balance.total);
```

### Proof of Concept

1. Alice registers her account with `storage_deposit`, depositing `X` NEAR → `total = X`, `available = X - min_required`.
2. Alice calls `ft_transfer_call` with `native_token_fee = Y` and a pre-funded message account holding `Y` NEAR.
3. `try_to_transfer_balance_from_message_account` runs: `available += Y`, `total` unchanged → `total = X`, `available = X - min_required + Y`.
4. Alice calls `storage_withdraw(None)` → `to_withdraw = X - min_required + Y`; `total.checked_sub(to_withdraw)` underflows → **panic**. Alice cannot withdraw her full balance.
5. Alice calls `storage_unregister(force=false)` → `total.saturating_sub(available) = 0 ≠ min_required` → **panic**.
6. Alice calls `storage_unregister(force=true)` → account removed; any pending-transfer storage refunds are silently dropped. The `Y` NEAR from the message account is effectively lost to Alice unless she accepts losing pending-transfer refunds. [9](#0-8)

### Citations

**File:** near/omni-bridge/src/storage.rs (L158-162)
```rust
            |mut storage| {
                storage.total = storage.total.saturating_add(amount);
                storage.available = storage.available.saturating_add(amount);
                storage
            },
```

**File:** near/omni-bridge/src/storage.rs (L193-205)
```rust
        let to_withdraw = amount.unwrap_or(storage.available);
        storage.total = storage.total.checked_sub(to_withdraw).near_expect(
            StorageError::NotEnoughStorageBalance {
                requested: to_withdraw,
                available: storage.total,
            },
        );
        storage.available = storage.available.checked_sub(to_withdraw).near_expect(
            StorageError::NotEnoughStorageBalance {
                requested: to_withdraw,
                available: storage.available,
            },
        );
```

**File:** near/omni-bridge/src/storage.rs (L222-228)
```rust
        if !force.unwrap_or_default() {
            require!(
                storage.total.saturating_sub(storage.available)
                    == self.required_balance_for_account(),
                BridgeError::StoragePendingTransfers.as_ref()
            );
        }
```

**File:** near/omni-bridge/src/storage.rs (L260-290)
```rust
    pub(crate) fn try_to_transfer_balance_from_message_account(
        &mut self,
        account_id: &AccountId,
        native_fee: NearToken,
        storage_payer: &AccountId,
        required_storage_payer_balance: NearToken,
    ) -> Result<(), StorageError> {
        let balance = self
            .accounts_balances
            .get(account_id)
            .ok_or(StorageError::MessageAccountNotRegistered)?;

        if balance.total < native_fee {
            return Err(StorageError::NotEnoughBalanceForFee);
        }

        let mut storage = self
            .accounts_balances
            .get(storage_payer)
            .ok_or(StorageError::SignerNotRegistered)?;

        storage.available = storage.available.saturating_add(balance.total);

        if storage.available < required_storage_payer_balance.saturating_add(native_fee) {
            return Err(StorageError::SignerNotEnoughBalance);
        }

        self.accounts_balances.insert(storage_payer, &storage);
        self.accounts_balances.remove(account_id);
        Ok(())
    }
```

**File:** near/omni-bridge/src/lib.rs (L566-573)
```rust
        if self
            .try_to_transfer_balance_from_message_account(
                &message_storage_account_id,
                NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
                &signer_id,
                required_storage_balance,
            )
            .is_ok()
```

**File:** near/omni-bridge/src/lib.rs (L635-643)
```rust
        if let Err(err) = self.try_to_transfer_balance_from_message_account(
            &message_storage_account_id,
            NearToken::from_yoctonear(transfer_message.fee.native_fee.0),
            &storage_owner,
            self.required_balance_for_init_transfer_message(transfer_message.clone()),
        ) {
            env::log_str(&format!("Error paying native fee and storage: {err}"));
            return transfer_message.amount;
        }
```

**File:** near/omni-bridge/src/lib.rs (L2205-2208)
```rust
        if let Some(mut storage) = self.accounts_balances.get(&transfer.owner) {
            storage.available = storage.available.saturating_add(refund);
            self.accounts_balances.insert(&transfer.owner, &storage);
        }
```
