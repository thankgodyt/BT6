Looking at the vulnerability class — **fee/balance mis-accounting causing permanent fund lockup** — I need to find an analog in the NEAR Omni Bridge where wrong arithmetic in a fee-related accounting function causes funds to become permanently inaccessible.

After searching the codebase, I found a direct analog in `near/omni-bridge/src/storage.rs`.

---

### Title
Native Fee Permanently Locked Due to Missing `total` Update in `try_to_transfer_balance_from_message_account` - (File: `near/omni-bridge/src/storage.rs`)

### Summary
`try_to_transfer_balance_from_message_account` is supposed to credit the native fee from a dedicated message account to the `storage_payer`. It updates only `storage.available` but never updates `storage.total`. Because `storage_withdraw` enforces `total` as the withdrawal ceiling, the credited native fee is permanently inaccessible for withdrawal — it is removed from the message account but cannot be recovered by the storage_payer.

### Finding Description

The function is documented as: *"Deducts the total balance from `account_id` and credits it to `storage_payer`."*

The implementation:

```rust
storage.available = storage.available.saturating_add(balance.total);
// storage.total is NEVER updated

self.accounts_balances.insert(storage_payer, &storage);
self.accounts_balances.remove(account_id);   // message account destroyed
``` [1](#0-0) 

After this call:
- `storage_payer.available` = `old_available + balance.total` (inflated)
- `storage_payer.total` = `old_total` (unchanged)

The `storage_withdraw` function uses `amount.unwrap_or(storage.available)` as the withdrawal target, then enforces:

```rust
storage.total = storage.total.checked_sub(to_withdraw).near_expect(...)
storage.available = storage.available.checked_sub(to_withdraw).near_expect(...)
``` [2](#0-1) 

If `to_withdraw = storage.available` and `available > total`, then `total.checked_sub(available)` panics (overflow-checks = true). The storage_payer is therefore capped at withdrawing only `old_total`, not `old_total + balance.total`. The native fee that was removed from the message account is permanently locked in the contract with no recovery path.

### Impact Explanation

A user initiates a transfer with a non-zero `native_token_fee`. That fee is deposited into a dedicated message account. When `try_to_transfer_balance_from_message_account` is called, the message account is destroyed (`accounts_balances.remove(account_id)`) and the NEAR tokens it held are supposed to be credited to the storage_payer (relayer). Because `total` is never updated, those NEAR tokens are permanently locked in the contract — the relayer cannot withdraw them via `storage_withdraw`. This is a direct loss of native NEAR funds: the fee paid by the user disappears into the contract with no mechanism to recover it.

### Likelihood Explanation

Any unprivileged bridge user can trigger this by setting a non-zero `native_token_fee` in `InitTransferMsg`. The path is: `ft_transfer_call` → `ft_on_transfer` → bridge processes native fee → `try_to_transfer_balance_from_message_account` is called. No special role or privilege is required on the user's side.

### Recommendation

Update `storage.total` alongside `storage.available` so the credited balance is fully withdrawable:

```rust
storage.total = storage.total.saturating_add(balance.total);
storage.available = storage.available.saturating_add(balance.total);
```

### Proof of Concept

1. User calls `ft_transfer_call` with `InitTransferMsg { native_token_fee: U128(1_000_000_000_000_000_000_000_000), fee: U128(0), ... }` — 1 NEAR as native fee.
2. The bridge deposits 1 NEAR into a dedicated message account for the transfer.
3. `try_to_transfer_balance_from_message_account` is called with `balance.total = 1 NEAR`.
4. `storage_payer.available` increases by 1 NEAR; `storage_payer.total` stays at its original value (e.g., 0.1 NEAR).
5. The message account is deleted — the 1 NEAR is now only reflected in `available`, not `total`.
6. The relayer calls `storage_withdraw` with no amount (defaults to `available`). The call panics because `total.checked_sub(available)` underflows (`0.1 - 1.1 NEAR`).
7. The relayer calls `storage_withdraw(Some(0.1 NEAR))` — succeeds, but only recovers their original deposit. The 1 NEAR native fee is permanently locked. [3](#0-2) [4](#0-3)

### Citations

**File:** near/omni-bridge/src/storage.rs (L186-211)
```rust
    #[payable]
    pub fn storage_withdraw(&mut self, amount: Option<NearToken>) -> StorageBalance {
        assert_one_yocto();
        let account_id = env::predecessor_account_id();
        let mut storage = self
            .storage_balance_of(&account_id)
            .near_expect(StorageError::AccountNotRegistered(account_id.clone()));
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

        self.accounts_balances.insert(&account_id, &storage);

        Promise::new(account_id).transfer(to_withdraw).detach();

        storage
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
