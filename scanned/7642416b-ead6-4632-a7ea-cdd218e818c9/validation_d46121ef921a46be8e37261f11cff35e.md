### Title
Unguarded Parallel Cross-Contract Calls in `swap_migrated_token` Cause Permanent Token Loss — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

The `swap_migrated_token` helper in `near/omni-bridge/src/lib.rs` issues `burn.and(mint)` as two parallel, detached cross-contract promises with **no failure callback**. Because `ft_on_transfer` returns `U128(0)` (consume all tokens, no refund) synchronously before those promises execute, any panic inside the `mint` leg permanently destroys the user's old tokens without crediting them with new tokens.

---

### Finding Description

When a user sends `old_token` to the bridge with the `SwapMigratedToken` message, the bridge's `ft_on_transfer` handler dispatches the swap and immediately returns `U128(0)`:

```rust
// near/omni-bridge/src/lib.rs  lines 275-279
BridgeOnTransferMsg::SwapMigratedToken => {
    self.swap_migrated_token(sender_id, token_id, amount)
        .detach();
    PromiseOrPromiseIndexOrValue::Value(U128(0))
}
```

`swap_migrated_token` itself creates two **parallel** promises with no attached callback:

```rust
// near/omni-bridge/src/lib.rs  lines 2749-2752
let burn = ext_token::ext(old_token).burn(amount);
let mint = ext_token::ext(new_token).mint(sender_id, amount, None);
burn.and(mint)
```

The `burn` call succeeds unconditionally (the bridge is the controller of `old_token`). The `mint` call invokes `internal_deposit` on the new token contract, which **panics** if the recipient account (`sender_id`) is not registered in `new_token`. Because the two promises are parallel and independent, the `burn` receipt is committed regardless of whether `mint` succeeds or fails. There is no callback to detect the failure and re-credit the user.

Crucially, by the time `burn` and `mint` execute asynchronously, the `old_token` contract has already processed the `U128(0)` return value from `ft_on_transfer` and has **not** refunded any tokens to the user. There is no recovery path.

---

### Impact Explanation

Any user who holds `old_token` and attempts to swap it for `new_token` without first registering their account in the `new_token` contract will have their entire transferred amount permanently burned. The tokens are irreversibly destroyed: the `old_token` balance is reduced, the `new_token` balance is never increased, and no refund is issued. This constitutes **permanent loss of bridged funds**.

---

### Likelihood Explanation

The entry path is fully unprivileged: any token holder can call `ft_transfer_call` on `old_token` with the `SwapMigratedToken` message. Token migrations are a documented, supported feature (`migrate_deployed_token`). Users who have never interacted with the `new_token` contract — a common situation immediately after a migration — will not have storage registered and will silently lose their funds. No special role, leaked key, or admin action is required beyond the DAO having previously called `migrate_deployed_token`.

---

### Recommendation

Attach a callback to the `burn.and(mint)` promise chain that inspects the result of `mint`. If `mint` failed, the callback should re-mint the equivalent amount of `old_token` back to the user (or hold it in escrow for manual recovery). Alternatively, check whether `sender_id` has storage registered in `new_token` **before** burning, and revert the entire operation (returning the full amount to the caller via `ft_on_transfer`'s return value) if registration is absent.

---

### Proof of Concept

1. DAO calls `migrate_deployed_token(Eth, old_token, new_token)`.
2. User `alice` holds 1000 units of `old_token` but has **never** called `storage_deposit` on `new_token`.
3. Alice calls `old_token.ft_transfer_call(bridge, 1000, '{"SwapMigratedToken": null}')`.
4. `old_token` transfers 1000 units to the bridge and calls `bridge.ft_on_transfer(alice, 1000, ...)`.
5. Bridge executes `swap_migrated_token(alice, old_token, 1000).detach()` and returns `U128(0)`.
6. `old_token` sees `U128(0)` → no refund issued to Alice.
7. Async: `burn(1000)` executes on `old_token` → bridge's balance decreases by 1000. ✓
8. Async: `mint(alice, 1000, None)` executes on `new_token` → `internal_deposit` panics because Alice is not registered. ✗
9. Alice has lost 1000 units of `old_token` permanently; her `new_token` balance remains 0. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** near/omni-token/src/lib.rs (L124-144)
```rust
#[near]
impl MintAndBurn for OmniToken {
    #[payable]
    fn mint(
        &mut self,
        account_id: AccountId,
        amount: U128,
        msg: Option<String>,
    ) -> PromiseOrValue<U128> {
        self.assert_controller();

        if let Some(msg) = msg {
            self.token
                .internal_deposit(&env::predecessor_account_id(), amount.into());

            self.ft_transfer_call(account_id, amount, None, msg)
        } else {
            self.token.internal_deposit(&account_id, amount.into());
            PromiseOrValue::Value(amount)
        }
    }
```
