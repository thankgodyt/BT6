Audit Report

## Title
Detached Promise in `ft_on_transfer` for `SwapMigratedToken` Silently Discards User Tokens on Failure - (File: `near/omni-bridge/src/lib.rs`)

## Summary

In `ft_on_transfer`, the `SwapMigratedToken` branch calls `swap_migrated_token(sender_id, token_id, amount).detach()` and unconditionally returns `U128(0)` to the NEP-141 token contract. Because `U128(0)` signals zero tokens to refund, the full transferred amount is consumed by the bridge regardless of whether the downstream `burn.and(mint)` promise chain succeeds. Any failure in that chain — including a `mint` panic due to unregistered storage on the new token — is silently swallowed, permanently destroying the user's tokens with no on-chain record and no refund path.

## Finding Description

`swap_migrated_token` constructs a two-step cross-contract promise chain:

```rust
fn swap_migrated_token(&mut self, sender_id: AccountId, old_token: AccountId, amount: U128) -> Promise {
    let new_token = self.migrated_tokens.get(&old_token)
        .near_expect(BridgeError::TokenNotMigrated);   // synchronous — panics before detach if absent
    let burn = ext_token::ext(old_token).burn(amount);
    let mint = ext_token::ext(new_token).mint(sender_id, amount, None);
    burn.and(mint)
}
```

The synchronous `near_expect` guard only protects against a missing mapping; it does not protect against failures inside the `burn` or `mint` cross-contract calls. Those calls execute asynchronously after `ft_on_transfer` returns. Because the promise is `.detach()`ed, NEAR's runtime discards the result receipt entirely — no callback fires, no state is rolled back, and no error is surfaced.

The NEP-141 protocol requires `ft_on_transfer` to return the number of tokens to refund. Returning `U128(0)` before the async swap completes means the token contract is told "all tokens consumed" unconditionally. The standard `ft_transfer_call` implementation on the token contract then skips the refund transfer. There is no second chance.

Concrete failure modes for `mint`:
- Recipient (`sender_id`) has not registered storage on `new_token`. NEP-141 `mint` implementations typically panic on unregistered accounts.
- `new_token` contract is paused or has been upgraded with a breaking interface.
- Gas exhaustion in the `burn.and(mint)` chain (two sequential cross-contract calls).

`migrate_deployed_token` registers storage only for the bridge contract itself on `new_token`, not for individual users, making the unregistered-storage failure mode realistic for any user who has not separately called `storage_deposit` on the new token.

## Impact Explanation

Permanent, irrecoverable loss of bridged user tokens. The user's old tokens are transferred to the bridge (step 1 of `ft_transfer_call`), the bridge returns `U128(0)` (no refund), and if `mint` fails the user receives nothing on either side. This matches the allowed Critical impact class: *loss or permanent freezing of bridged funds*.

## Likelihood Explanation

Medium. The `SwapMigratedToken` path is a migration utility invoked during token migration windows — precisely when misconfiguration risk (missing storage registration on the new token for individual users) is highest. The entry point is publicly reachable by any token holder via `ft_transfer_call`. No special privileges are required. The failure condition (unregistered storage on `new_token`) is a normal NEAR state that any user can be in.

## Recommendation

Replace the fire-and-forget `.detach()` with a callback that checks the promise result and refunds `amount` to `sender_id` on failure, returning `amount` from the callback (which becomes the NEP-141 refund value) and `U128(0)` on success. This mirrors the existing `resolve_fast_transfer` callback pattern already used in the codebase. The `ft_on_transfer` arm should return the chained promise directly (`.into()`) rather than a bare value, so the NEP-141 token contract waits for the callback result before deciding whether to refund.

## Proof of Concept

1. DAO calls `migrate_deployed_token(EVM, old_token.near, new_token.near)`. Bridge registers its own storage on `new_token.near` but does not register storage for individual users.
2. User holds `1_000_000` units of `old_token.near` and has **not** called `storage_deposit` on `new_token.near`.
3. User calls `ft_transfer_call` on `old_token.near`: recipient = bridge, amount = `1_000_000`, msg = `"SwapMigratedToken"`.
4. `old_token.near` transfers tokens to bridge, then calls bridge's `ft_on_transfer`.
5. Bridge executes `swap_migrated_token(user, old_token.near, 1_000_000).detach()` and returns `U128(0)`.
6. `old_token.near` sees `0` returned → issues no refund → `1_000_000` units are now held by the bridge.
7. The detached `burn.and(mint)` chain executes: `burn` succeeds (bridge holds the tokens and has burn rights), `mint` panics because `user` has no storage registration on `new_token.near`.
8. No callback fires. Bridge state is unchanged. User's `1_000_000` old tokens are burned; no new tokens are minted. Funds are permanently destroyed.