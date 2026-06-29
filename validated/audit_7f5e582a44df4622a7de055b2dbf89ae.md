Audit Report

## Title
Decimal Normalization Floor Division Permanently Freezes User Funds When `normalize_amount` Returns Zero - (File: near/omni-bridge/src/lib.rs)

## Summary
`sign_transfer` applies `normalize_amount` (floor division by `10^(origin_decimals − decimals)`) to `amount_without_fee` and panics with `ERR_INVALID_AMOUNT_TO_TRANSFER` if the result is zero. Because `init_transfer_internal` burns or locks the full user amount before `sign_transfer` is ever called, and no cancellation or refund path exists, any transfer whose net amount falls below the normalization divisor results in permanently frozen funds.

## Finding Description
`normalize_amount` performs integer floor division:

```rust
// near/omni-bridge/src/lib.rs L2784-2787
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

In `sign_transfer` (L475-485), this is applied to `amount_without_fee()`. If the result is zero, the function panics:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

The only guard at `init_transfer` time (L554-557) is `fee.fee < amount`, which does **not** ensure `normalize_amount(amount - fee) > 0`:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

By the time `sign_transfer` is called, `init_transfer_internal` (L1850-1857) has already burned (for bridged tokens) or locked (for native tokens) the full user amount:

```rust
if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
    self.lock_tokens_if_needed(..., transfer_message.amount.0);
}
```

The panic in `sign_transfer` does not roll back state or trigger any refund. No `cancel_transfer` function exists (confirmed by search). `update_transfer_fee` enforces `fee.fee >= current_fee.fee` (L399-401), meaning the fee can only be raised — which reduces `amount_without_fee` further, making recovery impossible.

The code comment at L2781-2783 acknowledges "dust stays locked/burned" for the sub-unit remainder case, but this vulnerability is categorically different: the **entire** transfer amount is frozen when `amount_without_fee` is wholly below the normalization divisor.

## Impact Explanation
This constitutes **permanent freezing of bridged funds**, matching the Critical impact class. For a token registered with `origin_decimals = 24` and `decimals = 6` (normalization divisor = `10^18`), any transfer with `amount_without_fee < 10^18` (i.e., less than 1 full NEAR-side unit) will have all tokens burned or locked with no recovery path. The transfer message remains in `pending_transfers` indefinitely, and every subsequent `sign_transfer` call will panic on the same transfer.

## Likelihood Explanation
The condition is reachable by any unprivileged user via `ft_transfer_call`. The `init_transfer` validation only checks `fee < amount`; it does not validate that `normalize_amount(amount - fee) > 0`. Tokens with large decimal gaps (e.g., 24 vs. 6) are a realistic and expected configuration for NEAR-to-EVM bridging. A user sending a "dust" amount or misunderstanding the decimal scaling triggers this silently and irreversibly. No special privileges or coordination are required.

## Recommendation
Add a normalization check at `init_transfer` time, before tokens are burned or locked, to reject transfers whose net amount would normalize to zero. This requires looking up the token's `Decimals` during `init_transfer`, mirroring the lookup already performed in `sign_transfer`:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This check must be inserted before the `burn_tokens_if_needed` / `lock_tokens_if_needed` calls in `init_transfer_internal`.

## Proof of Concept
1. DAO registers a token with `origin_decimals = 24`, `decimals = 6` (normalization divisor = `10^18`).
2. User calls `ft_transfer_call` with `amount = 500_000_000_000_000_000` (5×10^17, below the threshold). Fee = 0.
3. `init_transfer` passes: `fee (0) < amount (5×10^17)` ✓.
4. `init_transfer_internal` burns/locks the 5×10^17 tokens and stores the transfer message.
5. Relayer calls `sign_transfer`. `normalize_amount(5×10^17, {24, 6}) = 5×10^17 / 10^18 = 0`.
6. `require!(0 > 0, ...)` panics → `ERR_INVALID_AMOUNT_TO_TRANSFER`.
7. No state is rolled back. No `cancel_transfer` exists. `update_transfer_fee` can only raise the fee. Tokens are permanently frozen.

A local unit test can reproduce this by: (a) registering a token with the above decimals, (b) calling `ft_on_transfer` with the small amount to trigger `init_transfer_internal`, then (c) calling `sign_transfer` and asserting the panic, followed by (d) asserting the transfer message still exists in `pending_transfers` and the token balance is not restored.