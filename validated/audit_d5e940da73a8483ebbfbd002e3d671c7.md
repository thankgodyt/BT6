Audit Report

## Title
Non-Atomic Token Swap in `swap_migrated_token` Causes Permanent User Fund Loss - (File: `near/omni-bridge/src/lib.rs`)

## Summary

The `swap_migrated_token` function executes `burn.and(mint)` as detached parallel promises with no callback. Because `ft_on_transfer` returns `U128(0)` before the detached promise resolves, the NEP-141 contract irrevocably consumes the user's old tokens. If `mint` fails — due to the user not being registered on `new_token` or a race with the detached `storage_deposit` in `migrate_deployed_token` — the user's old tokens are burned and no new tokens are minted, resulting in permanent fund loss.

## Finding Description

In `ft_on_transfer`, the `SwapMigratedToken` branch detaches the swap promise and immediately returns `U128(0)`:

```rust
BridgeOnTransferMsg::SwapMigratedToken => {
    self.swap_migrated_token(sender_id, token_id, amount)
        .detach();
    PromiseOrPromiseIndexOrValue::Value(U128(0))
}
``` [1](#0-0) 

Returning `U128(0)` tells the NEP-141 old token contract to refund zero tokens — all transferred tokens are consumed — before the detached promise resolves.

`swap_migrated_token` then schedules two parallel cross-contract calls:

```rust
let burn = ext_token::ext(old_token).burn(amount);
let mint = ext_token::ext(new_token).mint(sender_id, amount, None);
burn.and(mint)
``` [2](#0-1) 

In NEAR, `promise_and` executes both sub-promises independently and in parallel. If `mint` panics, `burn` still executes. Since the combined promise is detached, there is no callback to detect failure and trigger a refund.

`mint` calls `internal_deposit(&account_id, amount.into())` directly: [3](#0-2) 

`FungibleToken::internal_deposit` panics if `account_id` has no storage registered on `new_token`. This is a standard NEP-141 invariant.

Additionally, `migrate_deployed_token` detaches its `storage_deposit` on `new_token` for the bridge itself: [4](#0-3) 

This creates a race: a user submitting `ft_transfer_call` in the same or next block as `migrate_deployed_token` may trigger `mint` before the bridge's own storage is registered on `new_token`, causing `mint` to fail even for the bridge's account.

There is no pre-check for `storage_balance_of` on `new_token` before accepting the swap, and no callback guards the detached promise chain.

## Impact Explanation

Any user whose `mint` call fails permanently loses their old tokens. The old tokens are burned from the bridge's balance (the bridge received them via `ft_transfer_call`), and no new tokens are minted. This is a direct, permanent, unrecoverable loss of bridged funds — matching the Critical impact class: *"loss or permanent freezing of bridged funds."*

## Likelihood Explanation

The failure condition is realistic and requires no attacker: any user holding old tokens at migration time who has not explicitly registered storage on `new_token` will trigger this path. Users are not automatically registered on the new token contract during migration. The race condition with the detached `storage_deposit` is also realistic since `migrate_deployed_token` does not wait for storage registration to complete before the mapping is live and swaps are accepted. Both conditions are triggerable by an ordinary external user through a standard `ft_transfer_call`.

## Recommendation

1. Replace the detached parallel promise with a sequential, callback-guarded flow: mint first, and only burn on confirmed mint success. On mint failure, return the full `amount` from `ft_on_transfer` to trigger a NEP-141 refund.
2. Alternatively, do not return `U128(0)` from `ft_on_transfer` for `SwapMigratedToken` until the full promise chain has been verified via a callback. Return the full `amount` on any failure to trigger a refund.
3. Require the user to have storage registered on `new_token` before accepting the swap (check via `storage_balance_of` before consuming tokens).
4. In `migrate_deployed_token`, await the `storage_deposit` result via a callback before making the migration mapping live.

## Proof of Concept

1. DAO calls `migrate_deployed_token(Eth, old_token, new_token)`. The detached `storage_deposit` on `new_token` is pending.
2. Alice holds 1000 `old_token` and calls `ft_transfer_call(bridge, 1000, "SwapMigratedToken")` — either before the `storage_deposit` completes, or without having registered storage on `new_token`.
3. Bridge's `ft_on_transfer` returns `U128(0)` immediately — Alice's 1000 `old_token` are irrevocably consumed by the NEP-141 contract.
4. The detached `burn.and(mint)` executes: `burn` succeeds (bridge's `old_token` balance is reduced by 1000); `mint` panics (no storage for Alice on `new_token`).
5. Alice has lost 1000 `old_token` and received 0 `new_token`. No recovery path exists in the contract.

### Citations

**File:** near/omni-bridge/src/lib.rs (L275-279)
```rust
            BridgeOnTransferMsg::SwapMigratedToken => {
                self.swap_migrated_token(sender_id, token_id, amount)
                    .detach();
                PromiseOrPromiseIndexOrValue::Value(U128(0))
            }
```

**File:** near/omni-bridge/src/lib.rs (L1651-1655)
```rust
        ext_token::ext(new_token.clone())
            .with_static_gas(STORAGE_DEPOSIT_GAS)
            .with_attached_deposit(NEP141_DEPOSIT)
            .storage_deposit(&env::current_account_id(), Some(true))
            .detach();
```

**File:** near/omni-bridge/src/lib.rs (L2749-2752)
```rust
        let burn = ext_token::ext(old_token).burn(amount);
        let mint = ext_token::ext(new_token).mint(sender_id, amount, None);

        burn.and(mint)
```

**File:** near/omni-token/src/lib.rs (L141-142)
```rust
            self.token.internal_deposit(&account_id, amount.into());
            PromiseOrValue::Value(amount)
```
