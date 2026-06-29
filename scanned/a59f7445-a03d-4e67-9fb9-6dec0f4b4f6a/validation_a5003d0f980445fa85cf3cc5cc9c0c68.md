### Title
`StorageBalance.total` Not Updated in `try_to_transfer_balance_from_message_account`, Permanently Locking User NEAR — (`File: near/omni-bridge/src/storage.rs`)

---

### Summary

In `near/omni-bridge/src/storage.rs`, the function `try_to_transfer_balance_from_message_account` credits the message account's full balance to the storage payer's `available` field but never updates the `total` field of the `StorageBalance`. This breaks the invariant `total >= available` and permanently locks the transferred NEAR inside the contract, because `storage_withdraw` uses `total` as the upper bound for withdrawals.

---

### Finding Description

When a user pre-funds a transfer by depositing NEAR to a dedicated message account, the bridge initiates the transfer by calling `try_to_transfer_balance_from_message_account`. This function is supposed to "deduct the total balance from `account_id` and credit it to `storage_payer`" (per its own comment).

The implementation only updates `storage.available`:

```rust
storage.available = storage.available.saturating_add(balance.total);
// ...
self.accounts_balances.insert(storage_payer, &storage);
self.accounts_balances.remove(account_id);
``` [1](#0-0) 

`storage.total` is never incremented. Compare this to `storage_deposit`, where both fields are always updated together:

```rust
storage.total = storage.total.saturating_add(amount);
storage.available = storage.available.saturating_add(amount);
``` [2](#0-1) 

After `try_to_transfer_balance_from_message_account` runs, the storage payer's `available` exceeds their `total`, breaking the invariant `total = available + storage_used`.

The `storage_withdraw` function enforces `total` as the withdrawal ceiling:

```rust
let to_withdraw = amount.unwrap_or(storage.available);
storage.total = storage.total.checked_sub(to_withdraw).near_expect(...);
storage.available = storage.available.checked_sub(to_withdraw).near_expect(...);
``` [3](#0-2) 

If the user attempts to withdraw their full `available` balance (which now exceeds `total`), `checked_sub` underflows and panics. The NEAR credited from the message account is permanently unwithdrawable.

---

### Impact Explanation

Any NEAR deposited to a message account and transferred via `try_to_transfer_balance_from_message_account` is permanently locked in the contract. The storage payer's `available` is inflated, but `total` is not, so `storage_withdraw` will always revert when the user tries to recover the credited NEAR. The funds are not stolen by an attacker but are irrecoverably frozen inside the bridge contract. This is escrow mis-accounting that permanently changes user balances — matching the critical impact criterion.

---

### Likelihood Explanation

The message account flow is a first-class supported path: any user who pre-funds a transfer with a native fee by depositing NEAR to a message account ID (derived from `calculate_storage_account_id`) and then calls `ft_transfer_call` will trigger this code path. No special role or privilege is required. The entry point is `ft_on_transfer` → `init_transfer` → `try_to_transfer_balance_from_message_account`. [4](#0-3) 

---

### Recommendation

Update `try_to_transfer_balance_from_message_account` to also increment `storage.total` by `balance.total`, mirroring the pattern used in `storage_deposit`:

```rust
storage.total = storage.total.saturating_add(balance.total);
storage.available = storage.available.saturating_add(balance.total);
```

This restores the invariant `total >= available` and allows the storage payer to withdraw the credited NEAR via `storage_withdraw`.

---

### Proof of Concept

1. Alice calls `storage_deposit` with a message account ID (e.g., `msg-abc.bridge.near`) and deposits 5 NEAR.
2. Alice calls `ft_transfer_call` to initiate a transfer with a native fee. `init_transfer` calls `try_to_transfer_balance_from_message_account`.
3. After the call:
   - Alice's `storage.available` increases by 5 NEAR (from the message account).
   - Alice's `storage.total` is **unchanged**.
   - The message account is removed.
4. Alice calls `storage_withdraw` with `amount = None` (withdraw all available). `to_withdraw = storage.available` (which now exceeds `storage.total`). `storage.total.checked_sub(to_withdraw)` underflows → panic.
5. Alice can only withdraw up to her original `storage.total`, permanently losing the 5 NEAR credited from the message account. [5](#0-4)

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
