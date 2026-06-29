Audit Report

## Title
Missing Minimum Transfer Amount Validation Causes Permanent Fund Freezing — (`near/omni-bridge/src/lib.rs`)

## Summary
The `init_transfer` function validates only that `fee < amount` before irreversibly burning or locking the full token amount. When the net transfer amount is too small to survive decimal normalization for the destination chain, `sign_transfer` will always panic with `InvalidAmountToTransfer`, and no cancel or refund path exists for the already-consumed tokens. The user's funds are permanently frozen.

## Finding Description
**Root cause:** `init_transfer` enforces only one pre-burn check at L554–557:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

After this passes, `init_transfer_internal` (L1829–1864) immediately burns (for deployed tokens) or locks (for native tokens) the full `transfer_message.amount` and returns `U128(0)` to the FT contract, consuming all tokens with no refund:

```rust
if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
    self.lock_tokens_if_needed(...);
} ...
U128(0)
```

Later, when a trusted relayer calls `sign_transfer` (L447–485), the bridge normalizes the net amount using floor division (L2784–2787):

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

`sign_transfer` then enforces (L482–485):

```rust
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

If `amount - fee < 10^(origin_decimals - decimals)`, `normalize_amount` returns `0` and `sign_transfer` always panics. Because `ft_on_transfer` already returned `U128(0)`, the FT contract consumed all tokens. No public cancel, withdraw, or refund entrypoint exists for pending transfers — `remove_transfer_message_without_refund` is an internal helper that removes the storage entry but does not restore burned or locked tokens.

**Concrete example:** Token with `origin_decimals = 24`, `decimals = 18` (decimal diff = 6, threshold = 1,000,000 units). A transfer of `amount = 500_000`, `fee = 0` passes the `fee < amount` check, burns 500,000 units, and then `normalize_amount(500_000, {24, 18}) = 0`, causing every subsequent `sign_transfer` call to panic permanently.

## Impact Explanation
Permanent freezing of bridged funds. Tokens are burned (deployed/bridged tokens) or locked (native tokens) in the NEAR bridge contract with no recovery path. This directly matches the Critical allowed impact: *"permanent freezing of bridged funds across NEAR, EVM, Solana, Starknet, Bitcoin, Zcash, or Wormhole-routed flows."*

## Likelihood Explanation
Any unprivileged user can trigger this via the standard public `ft_transfer_call` → `ft_on_transfer` → `init_transfer` flow. No special role or privilege is required to initiate the transfer. Tokens with a large decimal gap between their NEAR representation and destination chain (e.g., wNEAR: 24 vs. 18 EVM decimals, threshold ≈ 0.000001 NEAR) are directly affected. A user sending a dust amount, or a token with an unusually large decimal difference, triggers the freeze. The condition is easy to hit accidentally.

## Recommendation
Add a pre-burn validation in `init_transfer` (before `init_transfer_internal` is called) that checks the net amount survives normalization:

```rust
let decimals = self.token_decimals.get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);
let normalized = Self::normalize_amount(
    transfer_message.amount.0 - transfer_message.fee.fee.0,
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This mirrors the existing guard in `sign_transfer` (L482–485) but places it before the irreversible burn/lock step in `init_transfer_internal`.

## Proof of Concept
1. Register a token with `origin_decimals = 24`, `decimals = 18` (decimal diff = 6, threshold = 1,000,000 units).
2. Call `ft_transfer_call` with `amount = 500_000` and `fee = 0` targeting the NEAR bridge.
3. `init_transfer` passes the `fee < amount` check (0 < 500,000 ✓).
4. `init_transfer_internal` burns 500,000 units and returns `U128(0)` — tokens consumed.
5. Trusted relayer calls `sign_transfer` for this transfer.
6. `normalize_amount(500_000, {24, 18})` = `500_000 / 10^6` = `0`.
7. `require!(0 > 0, ...)` panics — `sign_transfer` always fails.
8. No cancel/refund path exists; 500,000 units are permanently frozen.

A local unit test can reproduce this by constructing a `TransferMessage` with the above parameters, calling `init_transfer_internal`, and asserting that `sign_transfer` panics with `InvalidAmountToTransfer` while the token balance is not restored.