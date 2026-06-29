### Title
Non-Atomic `burn.and(mint)` in `swap_migrated_token` Causes Permanent Token Loss on Mint Failure — (`near/omni-bridge/src/lib.rs`)

---

### Summary

`swap_migrated_token` issues a burn of the old token and a mint of the new token as two **parallel, independent** NEAR promises via `burn.and(mint)`. The result is `.detach()`ed in `ft_on_transfer`, so any mint failure is silently ignored. If the sender is not registered (no storage deposit) in the new token contract, `internal_deposit` panics, the mint promise fails, but the burn has already executed and is irreversible. The user permanently loses their old tokens and receives nothing.

---

### Finding Description

**Entry point — `ft_on_transfer` (lib.rs:275-279):**

```rust
BridgeOnTransferMsg::SwapMigratedToken => {
    self.swap_migrated_token(sender_id, token_id, amount)
        .detach();                          // ← failure of the joint promise is ignored
    PromiseOrPromiseIndexOrValue::Value(U128(0))  // ← 0 refunded; bridge keeps old tokens
}
``` [1](#0-0) 

**`swap_migrated_token` (lib.rs:2749-2752):**

```rust
let burn = ext_token::ext(old_token).burn(amount);
let mint = ext_token::ext(new_token).mint(sender_id, amount, None);
burn.and(mint)
``` [2](#0-1) 

`Promise::and()` in NEAR SDK schedules both sub-promises **in parallel**. Neither depends on the other's outcome; there is no rollback mechanism if one fails.

**`mint` in `omni-token` (lib.rs:140-142):**

```rust
} else {
    self.token.internal_deposit(&account_id, amount.into());  // panics if not registered
    PromiseOrValue::Value(amount)
}
``` [3](#0-2) 

`FungibleToken::internal_deposit` panics (NEAR panic = promise failure) when `account_id` has no storage registration in the new token. This causes the mint promise to fail.

**`migrate_deployed_token` only registers the bridge itself, not users (lib.rs:1651-1655):**

```rust
ext_token::ext(new_token.clone())
    .storage_deposit(&env::current_account_id(), Some(true))  // only bridge is registered
    .detach();
``` [4](#0-3) 

There is no guard anywhere in `swap_migrated_token` or `ft_on_transfer` that checks whether `sender_id` is registered in the new token before proceeding.

**`burn` in `omni-token` (lib.rs:146-151):**

```rust
fn burn(&mut self, amount: U128) {
    self.assert_controller();
    self.token.internal_withdraw(&env::predecessor_account_id(), amount.into());
}
``` [5](#0-4) 

The bridge holds the old tokens (because `ft_on_transfer` returned `U128(0)`), so `internal_withdraw` from the bridge's balance succeeds unconditionally.

---

### Impact Explanation

The execution sequence is:

1. User calls `old_token.ft_transfer_call(bridge, amount, "SwapMigratedToken")`.
2. NEP-141 transfers `amount` from user to bridge; `ft_on_transfer` is called.
3. Bridge returns `U128(0)` → bridge permanently holds old tokens.
4. `burn(old_token, amount)` executes → bridge's old-token balance is destroyed. **Irreversible.**
5. `mint(new_token, sender_id, amount, None)` executes → `internal_deposit` panics because `sender_id` is not registered → promise fails.
6. `.detach()` means the failure is never observed by the bridge.
7. User has lost `amount` of old tokens and received 0 new tokens. **Permanent loss.**

Impact: **Critical** — permanent, unrecoverable destruction of user funds during a legitimate migration flow. Any user who calls `swap_migrated_token` without first registering storage in the new token contract loses their entire transferred amount.

---

### Likelihood Explanation

- The migration flow is a production feature (DAO-callable `migrate_deployed_token` + user-callable `ft_transfer_call` with `SwapMigratedToken`).
- NEP-141 storage registration is a separate, non-obvious prerequisite. Many users will not know to call `storage_deposit` on the new token before swapping.
- No documentation, on-chain guard, or pre-check enforces registration before the swap.
- The loss can be triggered accidentally (not just by a malicious actor), making it a high-likelihood event during any real migration.

---

### Recommendation

Replace the parallel `burn.and(mint)` with a **sequential, callback-guarded** pattern:

1. Call `mint(new_token, sender_id, amount, None)` first.
2. In the callback, check success: if mint succeeded, call `burn(old_token, amount)`; if mint failed, refund the old tokens to `sender_id` via `ft_transfer`.

Alternatively, before issuing any promises, verify that `sender_id` is registered in the new token via `storage_balance_of`, and panic (causing `ft_resolve_transfer` to refund the full amount) if not registered.

The `.detach()` on the joint promise must also be replaced with a proper callback that can handle partial failure.

---

### Proof of Concept

```
# Localnet test (no mainnet interaction)
1. Deploy old_token (omni-token), new_token (omni-token), bridge.
2. DAO calls bridge.migrate_deployed_token(chain, old_token, new_token).
3. Register sender in old_token; mint 1000 old tokens to sender.
4. Do NOT call new_token.storage_deposit for sender.
5. sender calls old_token.ft_transfer_call(bridge, 1000, "SwapMigratedToken").
6. Assert: sender's old_token balance = 0 (burned).
7. Assert: sender's new_token balance = 0 (mint failed, not registered).
8. Assert: bridge's old_token balance = 0 (burned).
9. Net result: 1000 tokens permanently destroyed.
```

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

**File:** near/omni-token/src/lib.rs (L140-143)
```rust
        } else {
            self.token.internal_deposit(&account_id, amount.into());
            PromiseOrValue::Value(amount)
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
