Audit Report

## Title
Weaker Validation at `init_transfer` vs. `sign_transfer` Allows Permanent Freezing of Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

## Summary

`init_transfer` accepts user tokens with only a `fee < amount` guard, while `sign_transfer` additionally requires `normalize_amount(amount - fee) > 0`. For tokens where `origin_decimals > dest_decimals`, any `amount - fee` below the decimal-scaling divisor normalizes to zero via floor division, causing `sign_transfer` to permanently panic. No cancel or refund path exists, so the user's tokens are frozen in the bridge contract forever.

## Finding Description

**Stage 1 — `init_transfer`** stores the transfer with only:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [1](#0-0) 

**Stage 2 — `sign_transfer`** applies a stricter, additional check:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
``` [2](#0-1) 

`normalize_amount` performs floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [3](#0-2) 

The code comment at L2781–2783 acknowledges "dust stays locked/burned" for remainders, but this is distinct from the vulnerability: when the *entire* `amount - fee` is below the divisor, `normalize_amount` returns **zero**, and `sign_transfer` always panics — not just truncating a remainder, but making the transfer permanently unprocessable. [4](#0-3) 

`update_transfer_fee` cannot rescue the transfer because it only allows the fee to be **increased** (`fee.fee >= current_fee.fee`), which makes `amount - fee` smaller, worsening the normalization result: [5](#0-4) 

No cancel or refund entrypoint exists in the contract. The transfer message persists in storage indefinitely, and the locked tokens are irrecoverable.

## Impact Explanation

**Critical — Permanent freezing of bridged funds.** Any user who calls `ft_transfer_call` → `init_transfer` with an `amount - fee` value below `10^(origin_decimals - dest_decimals)` will have their tokens permanently locked. This directly matches the allowed impact: *permanent freezing of bridged funds across NEAR/EVM flows*. The `sign_transfer` call will always revert with `ERR_INVALID_AMOUNT_TO_TRANSFER`, and no recovery path exists in the contract.

## Likelihood Explanation

**Medium.** The condition is triggered when a token has more decimals on NEAR than on the destination EVM chain (e.g., 24 vs. 6, giving a divisor of `10^18`) and the user submits `amount - fee < 10^18`. This is a standard bridge configuration. The scenario can occur accidentally (a user sending a small amount without knowing the minimum transferable unit) or through a griefing path where an attacker front-runs or manipulates a victim into submitting a dust transfer. The decimal-difference configuration is common, not an edge case.

## Recommendation

Add the normalization check inside `init_transfer_internal` before accepting the user's tokens, mirroring the check already present in `sign_transfer`:

```rust
let token_address = self.get_token_address(destination_chain, token_id.clone())
    .near_expect(BridgeError::FailedToGetTokenAddress);
let decimals = self.token_decimals.get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This ensures no transfer can be stored that is guaranteed to fail at signing time, and the user's tokens are rejected (returned) at `ft_transfer_call` rather than locked.

## Proof of Concept

1. Register a token with `origin_decimals = 24`, `dest_decimals = 6` (divisor = `10^18`).
2. User calls `ft_transfer_call` with `amount = 500` (500 yocto-units) and `fee = 0`.
3. `init_transfer` check: `0 < 500` → **passes**. Tokens are transferred to the bridge locker and the transfer message is stored.
4. A trusted relayer calls `sign_transfer` for this transfer.
5. `normalize_amount(500 - 0, {origin:24, dest:6}) = 500 / 10^18 = 0`.
6. `require!(0 > 0, ...)` → **panics** with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
7. The transfer message remains in storage. The user's 500 yocto-units are permanently locked.
8. `update_transfer_fee` cannot help: increasing the fee only makes `amount - fee` smaller, keeping the normalized result at zero.
9. No cancel or refund function exists. Funds are irrecoverable.

### Citations

**File:** near/omni-bridge/src/lib.rs (L399-402)
```rust
                require!(
                    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
                    BridgeError::InvalidFee.as_ref()
                );
```

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
