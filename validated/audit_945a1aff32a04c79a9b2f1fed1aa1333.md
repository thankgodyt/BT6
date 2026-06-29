Audit Report

## Title
Decimal Normalization Floor Division Permanently Freezes User Funds When `normalize_amount` Returns Zero - (File: near/omni-bridge/src/lib.rs)

## Summary

`sign_transfer` applies `normalize_amount` (floor division) to `amount_without_fee` before signing. If the result is zero, the function panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`. Because tokens are already burned or locked in a prior committed transaction (`init_transfer_internal`), and no cancellation or fee-reduction path exists, those tokens are permanently frozen.

## Finding Description

`normalize_amount` performs integer floor division:

```rust
// near/omni-bridge/src/lib.rs L2784-2787
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

In `sign_transfer`, this is applied to `amount_without_fee()`:

```rust
// near/omni-bridge/src/lib.rs L475-485
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

The only guard at `init_transfer` time is `fee.fee < transfer_message.amount` (L554-557), which does **not** ensure `normalize_amount(amount - fee) > 0`.

By the time `sign_transfer` is called, `init_transfer_internal` has already burned (for bridged tokens) or locked (for native tokens) the full user amount in a prior committed transaction (L1850-1857). The panic in `sign_transfer` only rolls back state changes within that single transaction; the burn/lock from the earlier committed transaction is unaffected.

There is no `cancel_transfer` function. `update_transfer_fee` enforces `fee.fee >= current_fee.fee` (L400), so the fee can only be raised — it cannot rescue a transfer whose `amount_without_fee` is already below the normalization threshold. Raising the fee would only reduce `amount_without_fee` further, making the situation worse.

## Impact Explanation

Permanent freezing of bridged funds. For a token registered with `origin_decimals = 24` and `decimals = 6`, the normalization divisor is `10^18`. Any user who initiates a transfer with `amount_without_fee < 10^18` will have their tokens burned or locked with no recovery path. The transfer message remains in `pending_transfers` indefinitely, and every call to `sign_transfer` will panic. This matches the critical allowed impact: permanent freezing of bridged funds.

## Likelihood Explanation

Reachable by any unprivileged user via `ft_transfer_call`. The `init_transfer` validation only checks `fee < amount`; it does not validate that `normalize_amount(amount - fee) > 0`. Tokens with large decimal gaps (e.g., 24 vs 6) make the threshold large enough to trap ordinary user amounts. A user sending a "dust" amount, or a user who misunderstands the decimal scaling, triggers this silently and irreversibly.

## Recommendation

Add a normalization check at `init_transfer` time, before tokens are burned or locked, to reject transfers whose net amount would normalize to zero:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This requires looking up the token's `Decimals` during `init_transfer`, mirroring the lookup already performed in `sign_transfer`.

## Proof of Concept

1. DAO registers a token with `origin_decimals = 24`, `decimals = 6` (normalization divisor = `10^18`).
2. User calls `ft_transfer_call` with `amount = 500_000_000_000_000_000` (0.5 NEAR-side units, below the threshold).
3. `init_transfer` passes: `fee (0) < amount (5×10^17)` ✓.
4. `init_transfer_internal` burns/locks the `500_000_000_000_000_000` tokens and stores the transfer message in `pending_transfers`. This transaction commits.
5. Relayer calls `sign_transfer`. `normalize_amount(5×10^17, {24, 6}) = 5×10^17 / 10^18 = 0`.
6. `require!(0 > 0, ...)` panics → `ERR_INVALID_AMOUNT_TO_TRANSFER`. This transaction is rolled back, but the burn/lock from step 4 is not.
7. No state is rolled back for the burn/lock. Tokens are permanently frozen. `update_transfer_fee` cannot lower the fee to rescue the transfer.