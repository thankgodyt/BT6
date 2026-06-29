### Title
Non-Atomic `burn.and(mint)` in `swap_migrated_token` Causes Permanent Loss of User Funds — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

The `swap_migrated_token` function schedules a `burn` and a `mint` as parallel, non-atomic NEAR promises via `burn.and(mint)`. Because the enclosing `ft_on_transfer` handler immediately returns `U128(0)` (consuming the user's old tokens) and `.detach()`es the promise (no failure callback), any failure of the `mint` call leaves the user's old tokens permanently burned with no new tokens minted and no refund path.

---

### Finding Description

In `near/omni-bridge/src/lib.rs`, the `swap_migrated_token` function performs a token migration swap:

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

It is invoked from `ft_on_transfer` as:

```rust
BridgeOnTransferMsg::SwapMigratedToken => {
    self.swap_migrated_token(sender_id, token_id, amount)
        .detach();
    PromiseOrPromiseIndexOrValue::Value(U128(0))
}
```

Two structural flaws combine to create the vulnerability:

**Flaw 1 — Non-atomic parallel promises.** In NEAR Protocol, `Promise::and()` schedules both cross-contract calls as independent receipts. They execute in parallel and are **not** rolled back if the other fails. If `mint` panics (e.g., the bridge has no storage deposit on the new token contract, or the new token contract has a bug), the `burn` receipt has already been dispatched and will succeed independently, permanently destroying the user's old tokens.

**Flaw 2 — No failure callback.** The promise is `.detach()`ed, meaning there is no `#[private]` callback that could detect a failed `mint` and re-mint or refund. Simultaneously, `ft_on_transfer` returns `U128(0)`, so the NEP-141 `ft_transfer_call` mechanism does **not** refund the old tokens to the sender. Once `ft_on_transfer` returns, the old tokens are irrecoverably held by the bridge and will be burned regardless of whether the mint succeeds.

The symmetric failure (burn fails, mint succeeds) produces unauthorized minting: the user receives new tokens without the old ones being destroyed, inflating the new token supply.

---

### Impact Explanation

- **Primary:** If `mint` fails after `burn` succeeds, the user's old tokens are permanently destroyed with no new tokens issued — a direct, irreversible loss of bridged funds.
- **Secondary:** If `burn` fails while `mint` succeeds, the user receives new tokens without surrendering old ones — unauthorized minting that inflates the new token's supply and breaks the 1:1 migration invariant.

Both outcomes fall squarely within the critical impact scope: permanent loss of bridged funds and unauthorized minting.

---

### Likelihood Explanation

The entry point (`ft_transfer_call` → `ft_on_transfer` with `SwapMigratedToken`) is fully public and requires no privilege. The `mint` call can fail under realistic, non-adversarial conditions:

1. **Missing storage deposit:** NEP-141 tokens require a storage deposit before an account can hold a balance. If the bridge contract has not pre-registered on the new token contract, the `mint` call panics with a storage error — a common operational oversight during migrations.
2. **Gas exhaustion:** No explicit gas is attached to either `burn` or `mint` via `.with_static_gas()`. Gas is inherited from the parent call. If the user's `ft_transfer_call` provides insufficient prepaid gas, the `mint` receipt may fail while the `burn` receipt succeeds (receipts execute independently).
3. **New token contract bug:** Any panic in the new token's `mint` implementation causes the same outcome.

---

### Recommendation

Replace the parallel `burn.and(mint)` pattern with a sequential, callback-guarded pattern:

1. Call `burn` first.
2. In a `#[private]` callback, verify `burn` succeeded, then call `mint`.
3. In a second `#[private]` callback, verify `mint` succeeded; if it failed, re-mint the old tokens back to the user (or store a claimable refund).

Additionally, do **not** `.detach()` the promise — keep the callback chain attached so failures are observable and recoverable.

---

### Proof of Concept

1. Admin registers a migration: `migrated_tokens[old_token] = new_token`.
2. The bridge contract has **not** called `storage_deposit` on `new_token` for itself.
3. User calls `old_token.ft_transfer_call(bridge, amount, SwapMigratedToken)`.
4. `ft_on_transfer` returns `U128(0)` — old tokens are consumed by the bridge; no refund is possible from this point.
5. `swap_migrated_token` dispatches `burn.and(mint).detach()`.
6. `burn` receipt executes: bridge's `old_token` balance is destroyed. ✓
7. `mint` receipt executes: `new_token` panics with "account not registered" (no storage deposit). ✗
8. No callback exists to detect the failure or issue a refund.
9. User has lost `amount` of `old_token` and received 0 `new_token`. Funds are permanently destroyed. [1](#0-0) [2](#0-1)

### Citations

**File:** near/omni-bridge/src/lib.rs (L275-279)
```rust
            BridgeOnTransferMsg::SwapMigratedToken => {
                self.swap_migrated_token(sender_id, token_id, amount)
                    .detach();
                PromiseOrPromiseIndexOrValue::Value(U128(0))
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
