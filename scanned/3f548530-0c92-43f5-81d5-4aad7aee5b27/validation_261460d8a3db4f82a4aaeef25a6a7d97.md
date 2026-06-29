### Title
Non-Atomic Token Swap in `swap_migrated_token` Causes Permanent User Fund Loss - (File: `near/omni-bridge/src/lib.rs`)

### Summary

The `swap_migrated_token` function burns a user's old tokens and mints new tokens using a detached, non-atomic parallel promise (`burn.and(mint).detach()`). Because `ft_on_transfer` returns `U128(0)` immediately — before the detached promise resolves — the NEP-141 token contract consumes all of the user's old tokens regardless of whether the subsequent `mint` succeeds or fails. If the `mint` call fails for any reason, the user permanently loses their old tokens and receives nothing in return.

### Finding Description

When a token migration is registered via `migrate_deployed_token`, users can swap their old tokens for new ones by calling `ft_transfer_call` on the old token contract with the `SwapMigratedToken` message. The bridge's `ft_on_transfer` handler dispatches to `swap_migrated_token`: [1](#0-0) 

```rust
BridgeOnTransferMsg::SwapMigratedToken => {
    self.swap_migrated_token(sender_id, token_id, amount)
        .detach();
    PromiseOrPromiseIndexOrValue::Value(U128(0))
}
```

The return value `U128(0)` tells the NEP-141 token contract to refund zero tokens — i.e., all transferred tokens are consumed — **before** the detached promise resolves. [2](#0-1) 

```rust
fn swap_migrated_token(&mut self, sender_id: AccountId, old_token: AccountId, amount: U128) -> Promise {
    let new_token = self.migrated_tokens.get(&old_token)
        .near_expect(BridgeError::TokenNotMigrated);
    let burn = ext_token::ext(old_token).burn(amount);
    let mint = ext_token::ext(new_token).mint(sender_id, amount, None);
    burn.and(mint)
}
```

`burn.and(mint)` schedules two parallel cross-contract calls. In NEAR, parallel promises are independent: if `mint` panics or fails, `burn` still executes. Since the combined promise is `.detach()`ed, there is no callback to detect failure and refund the user. The user's old tokens are irrecoverably burned.

**Concrete failure conditions (no attacker required):**

1. **Race condition with `storage_deposit`**: `migrate_deployed_token` also detaches its `storage_deposit` call on `new_token`: [3](#0-2) 

   If a user submits their `ft_transfer_call` before this detached `storage_deposit` is processed (i.e., in the same or next block), the bridge has no storage on `new_token`, causing `mint` to fail.

2. **User not registered on `new_token`**: `OmniToken::mint` calls `internal_deposit(&account_id, amount)`: [4](#0-3) 

   If `sender_id` has not registered storage on `new_token`, `internal_deposit` panics, the `mint` fails, and the user's old tokens are burned with no recourse.

### Impact Explanation

Any user who calls `ft_transfer_call` on `old_token` with `SwapMigratedToken` and whose `mint` fails will permanently lose their old tokens. The old tokens are burned from the bridge's balance (the bridge received them via `ft_transfer_call`), and no new tokens are minted. This is a direct, permanent loss of bridged funds — the user's balance is reduced with no corresponding credit.

### Likelihood Explanation

The failure condition for unregistered storage on `new_token` is realistic: users holding old tokens at migration time are not automatically registered on the new token contract. The race condition with `storage_deposit` is also realistic since `migrate_deployed_token` detaches the storage registration. Any user who attempts the swap without first registering on `new_token` will silently lose funds.

### Recommendation

1. Replace the detached parallel promise with a sequential, callback-guarded flow: burn only after confirming mint succeeded, or mint first and burn only on success.
2. Alternatively, do not return `U128(0)` from `ft_on_transfer` for `SwapMigratedToken` until the full `burn.and(mint)` promise chain has been verified via a callback. Return the full `amount` on failure to trigger a refund.
3. Require the user to have storage registered on `new_token` before accepting the swap (check via `storage_balance_of` before consuming tokens).

### Proof of Concept

1. DAO calls `migrate_deployed_token(Eth, old_token, new_token)`. The `storage_deposit` on `new_token` is detached and pending.
2. Alice holds 1000 `old_token` and calls `ft_transfer_call(bridge, 1000, "SwapMigratedToken")` before the `storage_deposit` completes (or without having registered storage on `new_token`).
3. Bridge's `ft_on_transfer` returns `U128(0)` immediately — Alice's 1000 `old_token` are consumed by the NEP-141 contract.
4. The detached `burn.and(mint)` executes: `burn` succeeds (bridge's balance of `old_token` is reduced), `mint` panics (no storage for bridge or Alice on `new_token`).
5. Alice has lost 1000 `old_token` and received 0 `new_token`. No recovery path exists. [2](#0-1) [1](#0-0) [3](#0-2)

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

**File:** near/omni-token/src/lib.rs (L140-143)
```rust
        } else {
            self.token.internal_deposit(&account_id, amount.into());
            PromiseOrValue::Value(amount)
        }
```
