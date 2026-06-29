The code at line 281 confirms the claim exactly — only `storage.available` is updated, `storage.total` is not touched.

Audit Report

## Title
`try_to_transfer_balance_from_message_account` Increments `available` Without Incrementing `total`, Breaking `storage_withdraw` for Credited Native-Fee NEAR — (File: `near/omni-bridge/src/storage.rs`)

## Summary
`try_to_transfer_balance_from_message_account` credits the relayer's `StorageBalance.available` with the full balance of the message account but never increments `StorageBalance.total`. This violates the invariant `available <= total` maintained everywhere else in the contract. The resulting state causes `storage_withdraw` to panic on any withdrawal that reaches the credited amount, making the native-fee NEAR unwithdrawable via the standard withdrawal path and constituting a concrete fee mis-accounting impact.

## Finding Description
`StorageBalance` carries two independently tracked fields — `total` (cumulative deposits) and `available` (free-to-withdraw balance) — that every other mutation in the contract updates atomically.

`storage_deposit` increments both: [1](#0-0) 

`storage_withdraw` decrements both via `checked_sub`: [2](#0-1) 

`try_to_transfer_balance_from_message_account` breaks this invariant at line 281 — it adds `balance.total` to `storage.available` but leaves `storage.total` unchanged: [3](#0-2) 

After the call, for any non-zero `balance.total`:
- `storage_payer.available` = old `available` + `balance.total`
- `storage_payer.total` = old `total` (unchanged)
- Invariant violated: `available > total`

`storage_withdraw` computes `to_withdraw = amount.unwrap_or(storage.available)` and then calls `storage.total.checked_sub(to_withdraw)`. When `to_withdraw` exceeds `total` (which it will for any withdrawal that includes the credited native-fee portion), `checked_sub` returns `None` and the call panics. The relayer can withdraw at most their original `total` deposit via `storage_withdraw(Some(total))`, but the credited native-fee NEAR sitting in the excess `available` is unreachable through that function.

The only recovery path is `storage_unregister(force=Some(true))`, which refunds `required_balance_for_account() + storage.available`: [4](#0-3) 

This does return the credited NEAR, but it removes the relayer from the registry entirely, disrupting all in-flight operations and requiring re-registration.

## Impact Explanation
This is a concrete fee mis-accounting impact matching the allowed scope: *"fee mis-accounting… that changes user or protocol balances."* The native-fee NEAR deposited by the user into the message account is transferred to the relayer's `available` balance without a corresponding `total` update. The relayer's balance record is permanently inconsistent, and the credited fee NEAR cannot be withdrawn via `storage_withdraw`. Any relayer that does not resort to the destructive `storage_unregister(force=true)` path loses access to the credited fee NEAR for the lifetime of their registration.

## Likelihood Explanation
The trigger is any bridge transfer where the user supplies a non-zero `native_token_fee` in `InitTransferMsg` via `ft_transfer_call`. This is an unprivileged, publicly callable path. No special role or condition is required. Every such transfer unconditionally invokes `try_to_transfer_balance_from_message_account` during relayer processing, making the invariant violation repeatable and cumulative across all relayers processing native-fee transfers.

## Recommendation
Add a single line to keep `total` in sync with `available` inside `try_to_transfer_balance_from_message_account`, mirroring the pattern used in `storage_deposit`:

```rust
// near/omni-bridge/src/storage.rs ~line 281
storage.total     = storage.total.saturating_add(balance.total);   // ADD THIS
storage.available = storage.available.saturating_add(balance.total);
```

## Proof of Concept
1. User calls `ft_transfer_call` with `native_token_fee = 1_000_000_000_000_000_000_000_000` (1 NEAR). The bridge stores this in a dedicated message-account `StorageBalance { total: 1 NEAR, available: 1 NEAR }`.
2. Relayer processes the transfer. `try_to_transfer_balance_from_message_account` executes line 281: `storage.available += 1 NEAR`. `storage.total` is not touched.
3. Relayer's storage balance: `{ total: T, available: T + 1 NEAR }` — invariant violated.
4. Relayer calls `storage_withdraw(None)`: `to_withdraw = T + 1 NEAR`; `T.checked_sub(T + 1 NEAR)` → `None` → **panic**. Withdrawal fails.
5. Relayer calls `storage_withdraw(Some(T))`: succeeds; relayer recovers their original deposit. Remaining state: `{ total: 0, available: 1 NEAR }`. The 1 NEAR native fee is now permanently unwithdrawable via `storage_withdraw`.
6. Recovery requires `storage_unregister(force=true)`, which refunds `required_balance_for_account() + 1 NEAR` but removes the relayer from the registry, disrupting all in-flight operations. Any relayer that does not take this destructive step cannot access the credited fee NEAR.

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

**File:** near/omni-bridge/src/storage.rs (L232-235)
```rust
        let refund = self
            .required_balance_for_account()
            .saturating_add(storage.available);
        Promise::new(account_id).transfer(refund).detach();
```

**File:** near/omni-bridge/src/storage.rs (L276-288)
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
```
