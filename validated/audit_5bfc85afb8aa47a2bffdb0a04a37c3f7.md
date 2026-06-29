### Title
`try_to_transfer_balance_from_message_account` Updates `available` But Not `total`, Permanently Locking Native-Fee NEAR — (File: `near/omni-bridge/src/storage.rs`)

---

### Summary

`try_to_transfer_balance_from_message_account` credits the storage-payer's (relayer's) `StorageBalance.available` with the full balance of the message account, but never increments `StorageBalance.total`. This is the exact structural analog of the Beacon-Kit bug: one of two independently-tracked balance fields is updated while the other is silently skipped. The resulting invariant violation (`available > total`) makes `storage_withdraw` panic for any withdrawal that reaches the credited amount, permanently locking the native-fee NEAR inside the contract from the relayer's perspective.

---

### Finding Description

`StorageBalance` carries two fields that must always move together:

| Field | Meaning |
|---|---|
| `total` | Total NEAR ever deposited into this account |
| `available` | NEAR currently free to withdraw |

Every other mutation in the contract updates both fields atomically. `storage_deposit` increments both: [1](#0-0) 

`storage_withdraw` decrements both: [2](#0-1) 

`try_to_transfer_balance_from_message_account` breaks this invariant. It reads the message account's `balance.total`, adds it to the storage-payer's `available`, but leaves `total` unchanged: [3](#0-2) 

After the call:
- `storage_payer.available` = old `available` + `balance.total`
- `storage_payer.total` = old `total` (unchanged)

If `balance.total > 0`, then `available > total`, violating the invariant.

---

### Impact Explanation

`storage_withdraw` enforces the withdrawal ceiling via `total`, not `available`: [4](#0-3) 

When the relayer calls `storage_withdraw(None)`, `to_withdraw` defaults to `storage.available`. Because `available > total`, `storage.total.checked_sub(to_withdraw)` underflows and panics. The relayer is blocked from withdrawing the credited native-fee NEAR via `storage_withdraw`.

The only escape is `storage_unregister(force=Some(true))`, which refunds `required_balance_for_account() + storage.available`: [5](#0-4) 

But `storage_unregister` removes the account from the registry entirely, forcing an active relayer to re-register and re-deposit storage to resume operations. For any relayer that does not unregister, the credited NEAR is permanently inaccessible — it sits in the contract with no withdrawal path. This is a direct fee mis-accounting loss matching the Allowed Impact Scope.

---

### Likelihood Explanation

The function is triggered on every transfer where the user deposits a native NEAR fee into a dedicated message account. Any unprivileged bridge user can initiate such a transfer by calling `ft_transfer_call` with a non-zero `native_token_fee` in `InitTransferMsg`. The code path is unconditional once the transfer is processed; no special conditions are required.

---

### Recommendation

Add a single line to keep `total` in sync with `available` inside `try_to_transfer_balance_from_message_account`:

```rust
// near/omni-bridge/src/storage.rs  ~line 281
storage.total   = storage.total.saturating_add(balance.total);   // ADD THIS
storage.available = storage.available.saturating_add(balance.total);
```

This mirrors the pattern used in `storage_deposit` where both fields are always incremented together.

---

### Proof of Concept

1. User calls `ft_transfer_call` with `native_token_fee = 1_000_000_000_000_000_000_000_000` (1 NEAR). The bridge stores this in a dedicated message-account `StorageBalance { total: 1 NEAR, available: 1 NEAR }`.
2. Relayer processes the transfer. `try_to_transfer_balance_from_message_account` is called with `balance.total = 1 NEAR`.
3. Relayer's storage balance after the call: `{ total: T, available: T + 1 NEAR }` — `available` exceeds `total` by 1 NEAR.
4. Relayer calls `storage_withdraw(None)`:
   - `to_withdraw = T + 1 NEAR`
   - `storage.total.checked_sub(T + 1 NEAR)` → underflow → **panic**
5. Relayer calls `storage_withdraw(Some(T))`:
   - Succeeds; relayer recovers their original deposit.
   - Remaining state: `{ total: 0, available: 1 NEAR }` — the 1 NEAR native fee is now permanently unwithdrawable via `storage_withdraw`.
6. The 1 NEAR is locked in the contract. Recovery requires `storage_unregister(force=true)`, which removes the relayer from the registry and disrupts all in-flight operations. [6](#0-5)

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

**File:** near/omni-bridge/src/storage.rs (L231-236)
```rust

        let refund = self
            .required_balance_for_account()
            .saturating_add(storage.available);
        Promise::new(account_id).transfer(refund).detach();
        true
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
