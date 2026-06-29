Audit Report

## Title
Permanently Locked Funds Due to `normalize_amount` Returning Zero in `sign_transfer` - (File: `near/omni-bridge/src/lib.rs`)

## Summary
`init_transfer` accepts and locks user tokens after only verifying `fee < amount`, with no check that the normalized destination-chain amount is nonzero. When `sign_transfer` later computes `normalize_amount(amount_without_fee(), decimals)` via floor division and the result is zero, it panics unconditionally. Because no `cancel_transfer` or refund path exists anywhere in the contract, the locked tokens are permanently frozen.

## Finding Description
`init_transfer` stores the transfer and locks tokens after a single guard:

```rust
// near/omni-bridge/src/lib.rs L554-557
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

No downstream normalization check is performed at this stage. Later, `sign_transfer` (L475-485) computes:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

`normalize_amount` (L2784-2787) uses floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

For a token with `origin_decimals = 24`, `decimals = 18` (factor = 10^6), any `amount_without_fee() < 1_000_000` produces zero. The `require!` then panics, and every subsequent `sign_transfer` call for that `transfer_id` will panic identically. A search across the entire codebase confirms there is no `cancel_transfer` function and no user-accessible refund path, making the lock permanent.

The protocol's own comment at L2781-2783 acknowledges dust locking when `fee = 0` but only contemplates remainder dust, not the case where the entire net amount normalizes to zero.

## Impact Explanation
This is a concrete instance of **permanent freezing of bridged funds** — a Critical impact in the allowed scope. The user's tokens are irrecoverably locked in the NEAR bridge contract: `sign_transfer` is the sole finalization path for NEAR→EVM transfers, it will always revert for the affected `transfer_id`, and no cancellation or refund mechanism exists.

## Likelihood Explanation
Any unprivileged user can trigger this by calling `ft_on_transfer` with an amount below the normalization factor for the token's decimal pair. For the common NEAR (24 decimals) → EVM (18 decimals) pairing the threshold is 1,000,000 base units — a realistic small transfer. No special privileges, no external dependency failure, and no victim mistake beyond choosing a small amount are required. The condition is deterministic and repeatable.

## Recommendation
Add a normalization check inside `init_transfer` (or `init_transfer_internal`) before tokens are locked:

```rust
let decimals = self.token_decimals.get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);
require!(
    Self::normalize_amount(
        transfer_message.amount_without_fee()
            .near_expect(BridgeError::InvalidFee),
        decimals,
    ) > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

This mirrors the fix pattern suggested for M-9: enforce the downstream constraint at the entry point so tokens are never locked in an unrecoverable state.

## Proof of Concept
1. Register a token with `origin_decimals = 24`, `decimals = 18` (normalization factor = 10^6).
2. Call `ft_on_transfer` on the NEAR bridge with `amount = 500_000`, `fee = 0`, and a valid EVM recipient. `init_transfer` succeeds; 500,000 base units are locked.
3. Have a trusted relayer call `sign_transfer` for the resulting `transfer_id`.
4. Observe panic: `ERR_INVALID_AMOUNT_TO_TRANSFER` at `near/omni-bridge/src/lib.rs` L482-485 because `500_000 / 1_000_000 = 0`.
5. Repeat step 3 any number of times — the result is always the same panic.
6. Confirm via full-text search that no `cancel_transfer` or user-accessible refund function exists in the contract; the 500,000 units are permanently frozen. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** near/omni-bridge/src/lib.rs (L475-485)
```rust
        let amount_to_transfer = Self::normalize_amount(
            transfer_message
                .amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals,
        );

        require!(
            amount_to_transfer > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L554-557)
```rust
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L2781-2787)
```rust
    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
