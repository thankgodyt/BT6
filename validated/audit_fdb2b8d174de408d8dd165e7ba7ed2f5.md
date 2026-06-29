Audit Report

## Title
Unguarded Token Loss in `SwapMigratedToken` Branch of `ft_on_transfer` — No Refund on Swap Failure - (File: `near/omni-bridge/src/lib.rs`)

## Summary

The `SwapMigratedToken` branch of `ft_on_transfer` detaches a `burn.and(mint)` promise and unconditionally returns `U128(0)`, signalling the NEP-141 layer to keep all transferred tokens. Because `burn` and `mint` execute as independent, non-atomic receipts, a `mint` failure (e.g., the recipient is not storage-registered on the new token contract) leaves the `burn` committed with no rollback and no refund path, permanently destroying the user's funds.

## Finding Description

In `near/omni-bridge/src/lib.rs` the dispatcher handles `SwapMigratedToken` as:

```rust
BridgeOnTransferMsg::SwapMigratedToken => {
    self.swap_migrated_token(sender_id, token_id, amount)
        .detach();
    PromiseOrPromiseIndexOrValue::Value(U128(0))
}
``` [1](#0-0) 

`swap_migrated_token` schedules both cross-contract calls in parallel with no callback:

```rust
fn swap_migrated_token(&mut self, sender_id: AccountId, old_token: AccountId, amount: U128) -> Promise {
    let new_token = self.migrated_tokens.get(&old_token).near_expect(BridgeError::TokenNotMigrated);
    let burn = ext_token::ext(old_token).burn(amount);
    let mint = ext_token::ext(new_token).mint(sender_id, amount, None);
    burn.and(mint)
}
``` [2](#0-1) 

`burn` calls `internal_withdraw` on the bridge's balance of the old token (committed once the receipt executes): [3](#0-2) 

`mint` with `msg = None` calls `internal_deposit(&account_id, amount)`, which panics if `account_id` has no storage registration on the new token contract: [4](#0-3) 

In NEAR, `Promise::and()` schedules both sub-promises as independent action receipts. They are not atomic: a panic in the `mint` receipt does not roll back the already-committed `burn` receipt. The detached promise has no failure callback, and the `U128(0)` return value has already been committed to the NEP-141 `ft_transfer_call` resolver, so no refund of the old tokens is possible. Contrast this with `init_transfer_internal`, which returns `transfer_message.amount` on any internal failure to trigger the NEP-141 refund: [5](#0-4) 

No equivalent guard exists for `SwapMigratedToken`.

## Impact Explanation

This is a **Critical** impact matching "permanent freezing / loss of bridged funds." A user's old tokens are irreversibly burned on the old token contract while zero new tokens are minted, with no refund path. The loss is permanent and requires no privileged access to trigger.

## Likelihood Explanation

Token migration is a documented, supported bridge operation. Any user holding pre-migration tokens who calls `ft_transfer_call` with `msg: "SwapMigratedToken"` without first calling `storage_deposit` on the new token contract will trigger this loss. Storage registration is a separate, non-obvious prerequisite in NEAR's NEP-141 model. The `migrated_tokens` map is DAO-controlled, but the DAO cannot prevent individual users from omitting the registration step. The scenario requires no privileged access and is fully reachable via a standard public contract call.

## Recommendation

Replace the fire-and-forget pattern with a sequential promise chain that mints first and only burns on confirmed mint success, or add a `.then()` callback on `burn.and(mint)` that, on any failure, re-mints the old tokens back to the sender (or otherwise restores their balance). The safest restructuring is:

1. Call `mint` first.
2. In the mint callback, if successful, call `burn`; if failed, return the full `amount` to the NEP-141 layer (i.e., return `amount` from `ft_on_transfer` instead of `U128(0)`).

The pattern used by `init_transfer_internal` — returning `transfer_message.amount` on failure to trigger the NEP-141 refund — is the correct model.

## Proof of Concept

1. DAO sets `migrated_tokens[old_token] = new_token`.
2. User holds `N` units of `old_token` and has **not** called `storage_deposit` on `new_token`.
3. User calls `old_token.ft_transfer_call(receiver_id: bridge, amount: N, msg: "\"SwapMigratedToken\"")`.
4. Bridge's `ft_on_transfer` fires: `swap_migrated_token` schedules `burn(N).and(mint(user, N))` and detaches; returns `U128(0)`.
5. NEP-141 resolver sees `U128(0)` → bridge keeps all `N` old tokens (no refund).
6. `burn(N)` receipt executes on `old_token`: bridge's balance reduced by `N` — committed.
7. `mint(user, N)` receipt executes on `new_token`: `internal_deposit` panics because `user` is not registered — receipt fails, no new tokens minted.
8. Result: `N` old tokens permanently burned, `0` new tokens received, no refund. Funds are irreversibly lost.

### Citations

**File:** near/omni-bridge/src/lib.rs (L275-279)
```rust
            BridgeOnTransferMsg::SwapMigratedToken => {
                self.swap_migrated_token(sender_id, token_id, amount)
                    .detach();
                PromiseOrPromiseIndexOrValue::Value(U128(0))
            }
```

**File:** near/omni-bridge/src/lib.rs (L1838-1848)
```rust
        if self
            .try_update_storage_balance(
                storage_owner,
                required_storage_balance,
                NearToken::from_yoctonear(0),
            )
            .is_err()
        {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }
```

**File:** near/omni-bridge/src/lib.rs (L2738-2753)
```rust
    fn swap_migrated_token(
        &mut self,
        sender_id: AccountId,
        old_token: AccountId,
        amount: U128,
    ) -> Promise {
        let new_token = self
            .migrated_tokens
            .get(&old_token)
            .near_expect(BridgeError::TokenNotMigrated);

        let burn = ext_token::ext(old_token).burn(amount);
        let mint = ext_token::ext(new_token).mint(sender_id, amount, None);

        burn.and(mint)
    }
```

**File:** near/omni-token/src/lib.rs (L140-142)
```rust
        } else {
            self.token.internal_deposit(&account_id, amount.into());
            PromiseOrValue::Value(amount)
```

**File:** near/omni-token/src/lib.rs (L146-151)
```rust
    fn burn(&mut self, amount: U128) {
        self.assert_controller();

        self.token
            .internal_withdraw(&env::predecessor_account_id(), amount.into());
    }
```
