### Title
Non-Atomic Burn-and-Mint in `swap_migrated_token` Causes Permanent Token Loss - (File: near/omni-bridge/src/lib.rs)

---

### Summary

The `swap_migrated_token` function in the NEAR omni-bridge contract issues a `burn` and a `mint` as two independent parallel cross-contract calls joined with `Promise::and`. Because NEAR cross-contract calls are not atomic, if the `burn` succeeds but the `mint` fails, the user's old tokens are permanently destroyed while no new tokens are ever credited. The `ft_transfer_call` refund path then also fails because the bridge no longer holds the old tokens it already burned.

---

### Finding Description

When a user sends a migrated (old) bridge token to the omni-bridge via `ft_transfer_call`, the bridge's `ft_on_transfer` handler eventually calls `swap_migrated_token`:

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
``` [1](#0-0) 

`burn.and(mint)` schedules both cross-contract calls to execute in parallel. In NEAR, `Promise::and` does **not** provide atomicity: each sub-promise executes independently. If `burn` completes successfully (removing `amount` of old tokens from the bridge's account) and `mint` subsequently panics or fails (e.g., the recipient has no storage deposit in the new token contract, or the new token contract is paused), the joint promise resolves as failed.

The NEAR standard `ft_transfer_call` / `ft_resolve_transfer` callback on the old token contract interprets a failed promise result as "refund all tokens to the sender." However, the bridge's balance of old tokens is now zero — they were already burned. The refund transfer therefore also fails, leaving the user with neither old tokens nor new tokens.

The `burn` function on `OmniToken` withdraws from `env::predecessor_account_id()` (the bridge):

```rust
fn burn(&mut self, amount: U128) {
    self.assert_controller();
    self.token
        .internal_withdraw(&env::predecessor_account_id(), amount.into());
}
``` [2](#0-1) 

There is no callback attached to `burn.and(mint)` that could detect the `mint` failure and re-credit the user or re-mint the old tokens.

---

### Impact Explanation

A user who sends old (migrated) bridge tokens to the omni-bridge for swapping can permanently lose their entire token balance. The old tokens are burned from the bridge's escrow account, the new tokens are never minted, and the standard `ft_transfer_call` refund path fails because the bridge holds no old tokens to return. This constitutes a **critical loss of bridged funds** with no recovery path.

---

### Likelihood Explanation

The `mint` call will fail whenever the recipient (`sender_id`) has not registered a storage deposit in the new token contract — a common situation for users who are unaware of the migration or who have never interacted with the new token. It can also fail if the new token contract is paused or if the fixed `MINT_TOKEN_GAS` allocation (`Gas::from_tgas(5)`) is insufficient for the target token's `mint` implementation. [3](#0-2) 

Both failure modes are reachable by any unprivileged user without any special preconditions beyond holding migrated tokens.

---

### Recommendation

Replace the fire-and-forget `burn.and(mint)` pattern with a sequential, callback-guarded flow:

1. Call `mint` first.
2. In the `mint` callback, verify success.
3. Only if `mint` succeeded, call `burn`.
4. If `mint` failed, return the full `amount` from `ft_on_transfer` so the old token contract refunds the user (the bridge still holds the tokens at this point).

Alternatively, if the parallel pattern must be kept, attach a `then` callback to `burn.and(mint)` that detects `mint` failure and re-mints the old tokens back to the user before the `ft_resolve_transfer` refund path is invoked.

---

### Proof of Concept

1. The new token contract (`new_token`) requires storage registration (standard NEP-141 behavior).
2. Alice holds 1000 units of `old_token` (a migrated bridge token) but has **never** registered storage in `new_token`.
3. Alice calls `old_token.ft_transfer_call(bridge, 1000, msg)`.
4. Bridge's `ft_on_transfer` calls `swap_migrated_token(alice, old_token, 1000)`.
5. `burn.and(mint)` is scheduled: `burn` removes 1000 old tokens from the bridge's account; `mint` attempts to credit Alice in `new_token`.
6. `mint` panics: Alice has no storage deposit in `new_token`.
7. The joint promise fails; `ft_resolve_transfer` on `old_token` attempts to refund 1000 tokens to Alice.
8. The bridge's balance of `old_token` is 0 (already burned); the refund transfer panics.
9. Alice has lost 1000 old tokens and received 0 new tokens.

### Citations

**File:** near/omni-bridge/src/lib.rs (L73-73)
```rust
const MINT_TOKEN_GAS: Gas = Gas::from_tgas(5);
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

**File:** near/omni-token/src/lib.rs (L146-151)
```rust
    fn burn(&mut self, amount: U128) {
        self.assert_controller();

        self.token
            .internal_withdraw(&env::predecessor_account_id(), amount.into());
    }
```
