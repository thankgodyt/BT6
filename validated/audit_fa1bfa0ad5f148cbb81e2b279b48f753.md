### Title
Missing `storage.total` Update in `try_to_transfer_balance_from_message_account` Permanently Locks User Funds - (File: `near/omni-bridge/src/storage.rs`)

### Summary
`try_to_transfer_balance_from_message_account` credits the message account's full balance into `storage_payer.available` but never updates `storage_payer.total`. Because `storage_withdraw` uses `total` as the withdrawal ceiling, the credited amount can never be reclaimed, permanently locking the message account's deposited NEAR inside the bridge contract.

### Finding Description
When a transfer is initiated via `ft_on_transfer` → `init_transfer`, the bridge checks whether a pre-funded message account exists for the transfer. If it does, `try_to_transfer_balance_from_message_account` is called to absorb that account's balance into the signer's storage record. [1](#0-0) 

The function reads the message account's `balance.total`, adds it to `storage.available`, then removes the message account:

```rust
storage.available = storage.available.saturating_add(balance.total);
// ...
self.accounts_balances.insert(storage_payer, &storage);
self.accounts_balances.remove(account_id);
```

`storage.total` is never touched. After the call the `StorageBalance` for `storage_payer` satisfies `available > total`, violating the invariant that `total` tracks all deposited NEAR.

`storage_withdraw` enforces withdrawals against `total`, not `available`: [2](#0-1) 

```rust
let to_withdraw = amount.unwrap_or(storage.available);
storage.total = storage.total.checked_sub(to_withdraw)   // panics if to_withdraw > old_total
    .near_expect(...);
storage.available = storage.available.checked_sub(to_withdraw)
    .near_expect(...);
```

If the user calls `storage_withdraw` with no explicit amount, `to_withdraw` is set to the inflated `available`, which exceeds `total`, causing a panic. The user is forced to manually compute and pass an amount ≤ `total`. The delta `available − total` (equal to the message account's deposited balance) can never be withdrawn — it is permanently locked in the contract.

The analogous correct pattern is seen in `storage_deposit`, which always updates **both** fields together: [3](#0-2) 

```rust
storage.total = storage.total.saturating_add(amount);
storage.available = storage.available.saturating_add(amount);
```

`try_to_transfer_balance_from_message_account` performs only the second half of this pair.

### Impact Explanation
Every user who pre-funds a message account and then successfully triggers `init_transfer` via `ft_transfer_call` permanently loses the ability to withdraw the message account's deposited NEAR. The funds remain credited as `available` (usable for future storage operations) but are excluded from `total`, so they can never be reclaimed via `storage_withdraw`. This is a permanent, irreversible loss of bridged-adjacent user funds held in escrow by the NEAR bridge contract, constituting escrow mis-accounting that changes user balances.

### Likelihood Explanation
The message-account pre-funding path is a documented, publicly reachable feature: any unprivileged user can call `storage_deposit` targeting a message account ID and then call `ft_transfer_call` with a matching `external_id`. Every such successful invocation silently corrupts the `StorageBalance` of the signer. No special role or admin access is required.

### Recommendation
Update `storage.total` alongside `storage.available` inside `try_to_transfer_balance_from_message_account`, mirroring the pattern used in `storage_deposit`:

```diff
  storage.available = storage.available.saturating_add(balance.total);
+ storage.total = storage.total.saturating_add(balance.total);
``` [4](#0-3) 

### Proof of Concept

1. Alice calls `storage_deposit` for her own account (`signer_id`) with 10 NEAR → `total = 10 NEAR`, `available = 10 NEAR − min_storage`.
2. Alice calls `storage_deposit` for the computed message account ID with 2 NEAR → message account: `total = 2 NEAR`, `available = 2 NEAR − min_storage`.
3. Alice calls `ft_transfer_call` → `ft_on_transfer` → `init_transfer` with a matching `external_id`. `try_to_transfer_balance_from_message_account` succeeds:
   - `signer.available += 2 NEAR` (message account's `total`)
   - `signer.total` unchanged at 10 NEAR
   - Message account removed.
4. `init_transfer_internal` deducts `required_storage_balance` from `signer.available`.
5. Alice later calls `storage_withdraw` with no amount. `to_withdraw = signer.available` which now exceeds `signer.total = 10 NEAR` → **panic**. Alice can only withdraw up to 10 NEAR; the 2 NEAR from the message account is permanently locked. [5](#0-4) [6](#0-5)

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
