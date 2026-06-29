Audit Report

## Title
`try_to_transfer_balance_from_message_account` Credits `available` Without Updating `total`, Breaking `storage_withdraw` for Native Fees — (File: `near/omni-bridge/src/storage.rs`)

## Summary

`try_to_transfer_balance_from_message_account` increments the storage-payer's `StorageBalance.available` by the full message-account balance but leaves `StorageBalance.total` unchanged. This creates an invariant violation (`available > total`) that causes `storage_withdraw` to panic via `checked_sub` underflow whenever the relayer attempts to withdraw the credited native-fee NEAR. The only recovery path is `storage_unregister(force=true)`, which forcibly removes the relayer from the registry and disrupts all in-flight operations.

## Finding Description

`StorageBalance` carries two independently tracked fields: `total` (total NEAR ever deposited) and `available` (NEAR free to withdraw). Every other mutation keeps them in sync. `storage_deposit` increments both atomically: [1](#0-0) 

`storage_withdraw` decrements both atomically: [2](#0-1) 

`try_to_transfer_balance_from_message_account` breaks this invariant at line 281 — it adds `balance.total` to `storage.available` but never touches `storage.total`: [3](#0-2) 

After the call, if the message account held `F` yoctoNEAR and the relayer's prior state was `{ total: T, available: A }`, the resulting state is `{ total: T, available: A + F }`. Since `A + F > T` (assuming `A ≤ T` held before), the invariant is broken.

`storage_withdraw` enforces the withdrawal ceiling through `total`, not `available`: [4](#0-3) 

`to_withdraw` defaults to `storage.available` when no amount is specified. With `available > total`, `storage.total.checked_sub(to_withdraw)` underflows and panics. Even a partial withdrawal of exactly `T` succeeds but leaves the state `{ total: 0, available: F }`, after which any further `storage_withdraw` call panics because `total = 0`.

## Impact Explanation

This is a concrete fee mis-accounting impact within the allowed Critical scope. The native-fee NEAR credited to the relayer's `available` is inaccessible via `storage_withdraw`. The only escape is `storage_unregister(force=true)`: [5](#0-4) 

This refunds `required_balance_for_account() + storage.available`, which does recover the funds — but at the cost of removing the relayer from the registry entirely. `storage_unregister(force=false)` also fails because `storage.total.saturating_sub(storage.available)` evaluates to `0` (saturating underflow) rather than `required_balance_for_account()`: [6](#0-5) 

Any relayer that does not unregister has no withdrawal path for the credited native fees. For active relayers processing multiple transfers, forced unregistration disrupts all in-flight operations and requires re-registration. This constitutes fee mis-accounting that materially changes relayer balances, matching the allowed Critical impact class.

## Likelihood Explanation

The vulnerable function is triggered on every transfer where the user deposits a native NEAR fee into a dedicated message account. Any unprivileged user can initiate this by calling `ft_transfer_call` with a non-zero `native_token_fee` in `InitTransferMsg`. No special privileges, operator access, or unusual conditions are required. The code path is unconditional once the transfer is processed. Every such transfer permanently corrupts the relayer's `StorageBalance` invariant, and the effect is cumulative across multiple transfers.

## Recommendation

Add a single line to keep `total` in sync with `available` inside `try_to_transfer_balance_from_message_account`, mirroring the pattern used in `storage_deposit`:

```rust
// near/omni-bridge/src/storage.rs ~line 281
storage.total   = storage.total.saturating_add(balance.total);   // ADD THIS
storage.available = storage.available.saturating_add(balance.total);
```

This restores the invariant `available ≤ total` and allows `storage_withdraw` to function correctly for native fees.

## Proof of Concept

1. Relayer registers with deposit `D`, resulting in `{ total: D, available: D - required_balance_for_account() }`. Let `A = D - required_balance_for_account()`.
2. User calls `ft_transfer_call` with `native_token_fee = F > 0`. Bridge stores `F` in a message-account `StorageBalance { total: F, available: F }`.
3. Relayer processes the transfer. `try_to_transfer_balance_from_message_account` executes: relayer's state becomes `{ total: D, available: A + F }`.
4. Relayer calls `storage_withdraw(None)`:
   - `to_withdraw = A + F`
   - `D.checked_sub(A + F)` → underflow → **panic** (since `A + F > D` when `F > 0`).
5. Relayer calls `storage_withdraw(Some(D))`:
   - Succeeds; relayer recovers `D`.
   - Remaining state: `{ total: 0, available: F }`.
6. Relayer calls `storage_withdraw(None)` or `storage_withdraw(Some(F))`:
   - `0.checked_sub(F)` → underflow → **panic**. The `F` native fee is unwithdrawable via `storage_withdraw`.
7. Recovery via `storage_unregister(force=true)` refunds `required_balance_for_account() + F` but removes the relayer from the registry, disrupting all in-flight bridge operations.

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

**File:** near/omni-bridge/src/storage.rs (L232-235)
```rust
        let refund = self
            .required_balance_for_account()
            .saturating_add(storage.available);
        Promise::new(account_id).transfer(refund).detach();
```

**File:** near/omni-bridge/src/storage.rs (L276-289)
```rust
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
```
