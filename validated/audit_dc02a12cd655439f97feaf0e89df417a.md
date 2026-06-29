Audit Report

## Title
`normalize_amount` Floor Division Allows Zero-Amount Transfers to Be Permanently Locked in `sign_transfer` — (`near/omni-bridge/src/lib.rs`)

## Summary
`init_transfer` accepts deposits where the post-fee amount normalizes to zero under floor division, but `sign_transfer` unconditionally panics when the normalized amount is zero. Because no user-accessible cancellation path exists, any transfer stored with a sub-threshold amount is permanently frozen in the bridge contract with no recovery mechanism.

## Finding Description
`normalize_amount` performs integer floor division by `10^(origin_decimals - decimals)`: [1](#0-0) 

The inline comment at the function acknowledges dust locking but only in the context of remainders, not the case where the entire normalized result is zero: [2](#0-1) 

`sign_transfer` calls `normalize_amount` on `amount_without_fee()` and then requires the result to be strictly positive, panicking otherwise: [3](#0-2) 

`init_transfer` only validates `fee < amount`; it does not check that `normalize_amount(amount - fee) > 0`: [4](#0-3) 

The only place `remove_transfer_message` is called in `sign_transfer_callback` is when signing succeeds and `fee.is_zero()`: [5](#0-4) 

Since `sign_transfer` always panics for zero-normalized amounts, signing never succeeds, `remove_transfer_message` is never reached, and the transfer record persists indefinitely. There is no user-callable cancel or refund entry point.

## Impact Explanation
This directly satisfies the critical impact class: **permanent freezing of bridged funds**. Tokens deposited via `ft_transfer_call` → `ft_on_transfer` → `init_transfer` are locked in the bridge contract. If `normalize_amount(amount - fee) == 0`, every subsequent `sign_transfer` call panics unconditionally, and no user-accessible path exists to recover the tokens. This is not merely griefing — the depositing user's own funds are irrecoverably frozen.

## Likelihood Explanation
The condition is triggered by any token registered with `origin_decimals > decimals` (a standard bridging configuration) combined with a deposit amount below `10^(origin_decimals - decimals)` in the token's smallest unit. This can occur accidentally (dust amounts, UI rounding) or deliberately. No special privileges are required; any token holder can trigger this against themselves or be socially engineered into it. The preconditions are realistic in normal bridge usage.

## Recommendation
Add a normalization check inside `init_transfer_internal` (or before storing the transfer message) to reject deposits whose post-fee normalized amount is zero:

```rust
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This mirrors the existing check in `sign_transfer` and ensures the invariant is enforced at deposit time before tokens are locked.

## Proof of Concept
1. Register a token with `origin_decimals = 24`, `decimals = 18` (`diff_decimals = 6`, threshold = `1_000_000`).
2. Call `ft_transfer_call` with `amount = 500_000`, `fee = 0`. `init_transfer` accepts: `0 < 500_000` passes.
3. Tokens are now locked; a `TransferMessage` is stored.
4. Call `sign_transfer` for the stored `transfer_id`.
5. `normalize_amount(500_000, {24, 18}) = 500_000 / 1_000_000 = 0` (floor division).
6. `require!(0 > 0, ...)` panics — transaction fails.
7. Repeat step 4 indefinitely — always panics.
8. `sign_transfer_callback` is never reached; `remove_transfer_message` is never called.
9. Tokens are permanently frozen with no user-accessible recovery path.

A local unit test can reproduce this by constructing a `TransferMessage` with `amount = U128(500_000)`, registering decimals `{origin_decimals: 24, decimals: 18}`, and asserting that `sign_transfer` panics with `ERR_INVALID_AMOUNT_TO_TRANSFER` on every invocation.

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

**File:** near/omni-bridge/src/lib.rs (L655-658)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }
```

**File:** near/omni-bridge/src/lib.rs (L2781-2783)
```rust
    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
