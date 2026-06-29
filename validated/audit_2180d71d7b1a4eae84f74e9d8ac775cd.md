Audit Report

## Title
Unguarded Parallel `burn.and(mint)` in `swap_migrated_token` Causes Permanent Token Loss — (File: `near/omni-bridge/src/lib.rs`)

## Summary
`swap_migrated_token` issues `burn.and(mint)` as two independent, parallel NEAR receipts with no failure callback. Because `ft_on_transfer` synchronously returns `U128(0)` before either receipt executes, any panic in the `mint` leg (e.g., unregistered recipient in `new_token`) leaves the `burn` committed and the user's funds permanently destroyed with no recovery path.

## Finding Description
When a user sends `old_token` to the bridge with `SwapMigratedToken`, `ft_on_transfer` calls `swap_migrated_token(...).detach()` and immediately returns `U128(0)`, signaling to `old_token` that zero tokens should be refunded:

```rust
// near/omni-bridge/src/lib.rs L275-279
BridgeOnTransferMsg::SwapMigratedToken => {
    self.swap_migrated_token(sender_id, token_id, amount)
        .detach();
    PromiseOrPromiseIndexOrValue::Value(U128(0))
}
```

`swap_migrated_token` then constructs two independent receipts via `burn.and(mint)` with no attached callback:

```rust
// near/omni-bridge/src/lib.rs L2749-2752
let burn = ext_token::ext(old_token).burn(amount);
let mint = ext_token::ext(new_token).mint(sender_id, amount, None);
burn.and(mint)
```

In NEAR's execution model, `promise_a.and(promise_b)` schedules both as independent receipts. Failure of one does **not** roll back the other. The `burn` receipt calls `internal_withdraw` on the bridge's `old_token` balance (bridge is controller, so it always succeeds). The `mint` receipt calls `internal_deposit(&account_id, ...)` on `new_token`, which panics if `account_id` has no storage registration — standard behavior for `near_contract_standards::fungible_token::FungibleToken`. Because there is no callback inspecting the `mint` result, the panic is silently discarded. The `burn` is already committed, and `ft_on_transfer`'s `U128(0)` return has already told `old_token` not to refund anything.

## Impact Explanation
This constitutes **permanent, irreversible loss of bridged funds** for any user who swaps a migrated token without prior storage registration in `new_token`. The `old_token` balance is burned, the `new_token` balance is never credited, and no refund is issued. This directly matches the critical impact class: *loss or permanent freezing of bridged funds across NEAR flows*.

## Likelihood Explanation
The entry path is fully unprivileged — any holder of `old_token` can trigger it via `ft_transfer_call`. Token migration is a documented, supported feature. Users who have never interacted with `new_token` (the common case immediately after a migration) will not have storage registered. No leaked key, admin action, or special role is required beyond the DAO having previously called `migrate_deployed_token`. The scenario is realistic and repeatable.

## Recommendation
Attach a callback to the `burn.and(mint)` promise chain that inspects the `mint` result. If `mint` failed, the callback should re-mint the equivalent amount of `old_token` back to `sender_id` (or hold it in escrow). Alternatively, query `new_token`'s `storage_balance_of(sender_id)` **before** burning, and if storage is absent, return the full `amount` from `ft_on_transfer` (instead of `U128(0)`) to trigger an automatic refund, aborting the swap without any burn.

## Proof of Concept
1. DAO calls `migrate_deployed_token(Eth, old_token, new_token)` — sets up the migration mapping.
2. `alice` holds 1000 units of `old_token` and has never called `storage_deposit` on `new_token`.
3. Alice calls `old_token.ft_transfer_call(bridge, 1000, '{"SwapMigratedToken": null}')`.
4. `old_token` transfers 1000 units to the bridge and calls `bridge.ft_on_transfer(alice, 1000, ...)`.
5. Bridge executes `swap_migrated_token(alice, old_token, 1000).detach()` and returns `U128(0)`.
6. `old_token` sees `U128(0)` → no refund issued to Alice.
7. Async receipt 1: `burn(1000)` on `old_token` → bridge's balance decreases by 1000. ✓ (committed)
8. Async receipt 2: `mint(alice, 1000, None)` on `new_token` → `internal_deposit` panics (Alice not registered). ✗ (silently discarded, no rollback of receipt 1)
9. Alice has permanently lost 1000 units of `old_token`; her `new_token` balance remains 0.

A local integration test can confirm this by deploying both token contracts and the bridge on a NEAR sandbox, omitting `storage_deposit` for the recipient on `new_token`, and asserting that after the call sequence both balances are 0.