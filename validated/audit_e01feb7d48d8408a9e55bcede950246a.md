### Title
Token Migration Swap Ignores Decimal Differences Between Old and New Token — (`File: near/omni-bridge/src/lib.rs`)

### Summary

`swap_migrated_token` burns a user-supplied amount of an old (migrated) token and mints the **identical raw amount** of the new token with no decimal normalization. If the old and new tokens have different decimal precisions, every user who triggers the swap either loses funds or receives an inflated mint.

### Finding Description

The bridge maintains a `migrated_tokens` map (admin-set) that pairs an old token account with its replacement. When a user sends old tokens to the bridge via `ft_on_transfer`, the bridge calls `swap_migrated_token`: [1](#0-0) 

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
    let mint = ext_token::ext(new_token).mint(sender_id, amount, None);   // ← same raw amount

    burn.and(mint)
}
```

The function burns `amount` units of `old_token` and mints exactly `amount` units of `new_token`. There is **no decimal lookup, no normalization, and no assertion that the two tokens share the same precision**.

Contrast this with every other amount-handling path in the same contract, which explicitly fetches a `Decimals { decimals, origin_decimals }` record and applies `normalize_amount` / `denormalize_amount`: [2](#0-1) 

The `Decimals` struct that stores per-token precision is: [3](#0-2) 

`swap_migrated_token` never consults `self.token_decimals` at all.

### Impact Explanation

If `old_token` has 18 decimals and `new_token` has 6 decimals (a common real-world pairing, e.g., a NEAR-native stablecoin migrating to a 6-decimal representation):

- A user burns `1 × 10^18` raw units (= 1.0 old token).
- The bridge mints `1 × 10^18` raw units of new token (= **1 000 000 000 000** new tokens).

The protocol mints 10^12× more value than it destroyed, draining the new token's supply or the bridge's locked reserves. The inverse (old token with fewer decimals than new token) causes the user to receive far less than they burned — a direct loss of user funds. Both directions match the "balance manipulation / decimal normalization abuse" impact class.

### Likelihood Explanation

The `migrated_tokens` mapping is populated by an admin role. Token migrations are a normal, documented bridge operation (the mapping and `swap_migrated_token` exist precisely for this purpose). An admin who migrates a token whose decimal count differs from its successor — even by accident, or because the new token was deployed with a different standard — immediately exposes every subsequent user-triggered swap to the mis-accounting. No attacker capability beyond holding old tokens and calling `ft_transfer` to the bridge is required once the mapping is live.

### Recommendation

Before executing the burn-and-mint, fetch the `Decimals` records for both `old_token` and `new_token` from `self.token_decimals` and assert they share the same `origin_decimals` (or apply the appropriate scaling factor). Alternatively, add an explicit invariant check in the admin function that registers a migration entry, rejecting any pair whose decimal metadata does not match.

### Proof of Concept

1. Admin calls the migration-registration function, mapping `old_token` (18 decimals) → `new_token` (6 decimals).
2. Attacker calls `ft_transfer_call` on `old_token`, sending `1_000_000_000_000_000_000` (1.0 token) to the bridge with a `swap` message.
3. Bridge calls `swap_migrated_token(attacker, old_token, 1_000_000_000_000_000_000)`.
4. `burn(1_000_000_000_000_000_000)` destroys 1.0 old token.
5. `mint(attacker, 1_000_000_000_000_000_000, None)` mints **1 000 000 000 000** new tokens (each worth 1.0 in 6-decimal terms).
6. Attacker has extracted 10^12 times the value they deposited, at the expense of the bridge's new-token reserves. [4](#0-3)

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L2776-2787)
```rust
    fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount * (10_u128.pow(diff_decimals))
    }

    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```

**File:** near/omni-bridge/src/storage.rs (L131-136)
```rust
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decimals {
    pub decimals: u8,
    pub origin_decimals: u8,
}
```
