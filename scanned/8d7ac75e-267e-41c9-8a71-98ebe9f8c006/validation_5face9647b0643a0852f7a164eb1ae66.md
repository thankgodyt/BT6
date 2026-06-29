### Title
Unguarded Token Loss in `SwapMigratedToken` Branch of `ft_on_transfer` — No Refund on Swap Failure - (File: `near/omni-bridge/src/lib.rs`)

### Summary

The `ft_on_transfer` entry point in the NEAR bridge contract handles four message types. Three of them (`InitTransfer`, `FastFinTransfer`, `UtxoFinTransfer`) use callbacks or conditional return values to refund tokens when the operation fails. The fourth — `SwapMigratedToken` — unconditionally returns `U128(0)` (keep all tokens) and detaches the swap promise with no failure callback. If the internal `mint` call fails (e.g., the sender is not registered for storage on the new token contract), the old tokens are already burned and the user permanently loses their funds.

### Finding Description

In `near/omni-bridge/src/lib.rs`, the `ft_on_transfer` dispatcher handles `SwapMigratedToken` as follows:

```rust
BridgeOnTransferMsg::SwapMigratedToken => {
    self.swap_migrated_token(sender_id, token_id, amount)
        .detach();
    PromiseOrPromiseIndexOrValue::Value(U128(0))
}
``` [1](#0-0) 

The `swap_migrated_token` function schedules a parallel `burn.and(mint)` promise and returns it — but the caller immediately detaches it and returns `U128(0)` to the NEP-141 `ft_transfer_call` mechanism, signalling "keep all tokens":

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
``` [2](#0-1) 

`burn.and(mint)` schedules both cross-contract calls in parallel. In NEAR, cross-contract calls are not atomic across receipts: if `burn` succeeds and `mint` panics (e.g., because `sender_id` has no storage registration on the new token contract, causing `internal_deposit` to panic), the burn is already committed and cannot be rolled back. The `ft_on_transfer` return value of `U128(0)` has already been committed, so the NEP-141 layer does not refund the old tokens either.

Contrast this with the `InitTransfer` branch, which properly returns the full `amount` to trigger a refund when the internal operation fails:

```rust
if self.try_update_storage_balance(...).is_err() {
    self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
    return transfer_message.amount;  // triggers NEP-141 refund
}
``` [3](#0-2) 

No equivalent safety net exists for `SwapMigratedToken`.

### Impact Explanation

If the `mint` call fails for any reason (sender not registered on the new token, new token contract paused, gas exhaustion in the mint receipt, etc.), the user's old tokens are permanently burned with no new tokens minted and no refund path. This constitutes a **critical, irreversible loss of bridged funds** for the affected user, triggered entirely by a public, unprivileged `ft_transfer_call` invocation.

### Likelihood Explanation

Token migration is a supported, documented bridge operation. A user who holds old (pre-migration) tokens and calls `ft_transfer_call` with `msg: "SwapMigratedToken"` without first registering storage on the new token contract will trigger this loss. Storage registration is a separate, non-obvious prerequisite in NEAR's NEP-141 model. The `migrated_tokens` map is DAO-controlled, but the DAO cannot prevent individual users from omitting the storage registration step. The scenario is realistic and requires no privileged access.

### Recommendation

Replace the fire-and-forget detach pattern with a callback chain that checks whether the mint succeeded before committing the burn, or restructure the operation to mint first and only burn on confirmed success. At minimum, add a callback on the `burn.and(mint)` promise that, on any failure, returns the full `amount` to the NEP-141 layer (so the old tokens are refunded rather than kept by the bridge). The pattern used by `init_transfer_internal` — returning `transfer_message.amount` on failure — is the correct model to follow.

### Proof of Concept

1. DAO sets `migrated_tokens[old_token] = new_token`.
2. User holds `N` units of `old_token` and has **not** called `storage_deposit` on `new_token`.
3. User calls `old_token.ft_transfer_call(receiver_id: bridge, amount: N, msg: "\"SwapMigratedToken\"")`.
4. Bridge's `ft_on_transfer` fires: `swap_migrated_token` schedules `burn(N).and(mint(user, N))` and detaches; returns `U128(0)`.
5. NEP-141 layer sees `U128(0)` → bridge keeps all `N` old tokens.
6. `burn(N)` receipt executes: bridge's balance of `old_token` is reduced by `N` (committed).
7. `mint(user, N)` receipt executes: `internal_deposit` panics because `user` is not registered on `new_token`. Receipt fails; no new tokens are minted.
8. Result: user's `N` old tokens are burned, `0` new tokens received, no refund. Funds are permanently lost. [1](#0-0) [2](#0-1)

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
