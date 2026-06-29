Let me look at the NEAR promise model for `burn.and(mint)` and the `ft_on_transfer` return value more carefully.

### Title
Non-Atomic Token Migration: Burn Succeeds but Mint Fails Causes Permanent Fund Loss — (`near/omni-bridge/src/lib.rs`)

---

### Summary

`swap_migrated_token` issues a `burn.and(mint)` joint promise with no callback and `.detach()`s the result. `ft_on_transfer` simultaneously returns `U128(0)`, permanently accepting the old tokens. If the `mint` sub-promise fails (e.g., recipient not registered on the new token), the burn is already committed and irreversible, destroying the user's funds with no recovery path.

---

### Finding Description

The migration swap path is:

**`ft_on_transfer` → `swap_migrated_token`** (`near/omni-bridge/src/lib.rs`) [1](#0-0) 

The handler immediately returns `U128(0)` (keep all tokens) and detaches the burn+mint promise: [2](#0-1) 

`burn.and(mint)` schedules two **independent** action receipts in NEAR's async model. They execute in parallel with no atomicity guarantee. If `mint` panics, the burn receipt is already committed — NEAR does not roll back a sibling promise.

The `mint` function calls `internal_deposit(&account_id, amount.into())`: [3](#0-2) 

`internal_deposit` panics if `account_id` has no storage registration on the new token (NEAR FT standard requirement). `migrate_deployed_token` only registers the **bridge contract itself** on the new token — not individual users: [4](#0-3) 

Any user who has not explicitly called `storage_deposit` on the new token before swapping will trigger a mint panic. Since the new token is freshly deployed, no users are pre-registered.

---

### Impact Explanation

- Old tokens are transferred to the bridge via `ft_transfer_call`; `ft_on_transfer` returns `U128(0)` — they are permanently accepted.
- The burn sub-promise executes and destroys the bridge's balance of old tokens.
- The mint sub-promise panics (unregistered recipient) — new tokens are never created.
- No callback exists to detect the failure or refund the user.
- Result: **permanent, irreversible destruction of user funds** with no recovery mechanism.

---

### Likelihood Explanation

This is a near-certain outcome for any user who attempts `SwapMigratedToken` without first registering on the new token. Since the new token is freshly deployed and `migrate_deployed_token` does not pre-register users, the default state for all existing token holders is "unregistered on new token." A user who simply sends old tokens with the `SwapMigratedToken` message — the natural migration action — will lose their funds.

---

### Recommendation

Reverse the operation order: **mint first, then burn in a callback**. If mint fails, the old tokens are still held by the bridge and can be returned to the user via `ft_transfer`. Alternatively, add a `then` callback after `burn.and(mint)` that checks both sub-promise results and, on any failure, re-mints old tokens back to the user (or stores a claimable balance). A pre-flight `storage_balance_of` check before burning would also prevent the loss, though it adds a round-trip.

---

### Proof of Concept

```
1. Deploy old_token and new_token (OmniToken contracts).
2. Call migrate_deployed_token(old_token, new_token) on the bridge.
   → Bridge registers itself on new_token; users are NOT registered.
3. Mint 1000 old_token to alice.
4. Alice calls ft_transfer_call(bridge, 1000, '{"SwapMigratedToken": {}}') on old_token.
   → ft_on_transfer returns U128(0); bridge holds 1000 old tokens.
   → burn promise fires: bridge's old_token balance → 0 (committed).
   → mint promise fires: internal_deposit(alice, 1000) panics (alice not registered on new_token).
5. Assert: old_token.ft_total_supply() decreased by 1000.
6. Assert: new_token.ft_total_supply() unchanged (0).
7. Alice has 0 old tokens and 0 new tokens. Funds permanently lost.
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
