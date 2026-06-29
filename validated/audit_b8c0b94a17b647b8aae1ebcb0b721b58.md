All cited code references are confirmed in the repository. Let me verify the key claims:

**`init_transfer` fee check** (L554-557): Only `fee < amount` is checked. [1](#0-0) 

**`normalize_amount`** (L2784-2787): Floor division confirmed. [2](#0-1) 

**`sign_transfer` zero-amount guard** (L475-485): Fires after tokens are already locked. [3](#0-2) 

**`update_transfer_fee`** (L399-402): `fee.fee >= current_fee.fee` — fee can only increase. [4](#0-3) 

The inline doc comment at L2781-2783 explicitly acknowledges that when `fee = 0`, dust "stays locked/burned," confirming the protocol's awareness of floor-division truncation — but this only covers sub-unit dust, not the case where the entire `amount - fee` normalizes to zero. [5](#0-4) 

All technical claims in the submission are accurate and confirmed by the source code.

---

Audit Report

## Title
Missing `normalize_amount > 0` Guard in `init_transfer` Enables Permanent Token Lock - (File: `near/omni-bridge/src/lib.rs`)

## Summary
`init_transfer` validates only that `fee < amount`, but does not verify that `normalize_amount(amount - fee, decimals) > 0`. For tokens with a large decimal difference between origin and destination chains, a user can set a fee that leaves a net amount below the minimum transferable unit. Tokens are locked immediately on NEAR, but every subsequent `sign_transfer` call will revert with `ERR_INVALID_AMOUNT_TO_TRANSFER`. Because `update_transfer_fee` enforces `fee >= current_fee`, the fee cannot be lowered to recover the transfer, and no cancel/refund path exists for pending transfers, resulting in permanent freezing of the locked funds.

## Finding Description

`init_transfer` constructs the `TransferMessage` and applies a single fee guard:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

This check passes as long as `fee` is strictly less than `amount`, regardless of whether `amount - fee` survives decimal normalization. `normalize_amount` uses floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

For a token with `origin_decimals = 24`, `dest_decimals = 6` (`diff = 18`), any `amount - fee < 10^18` normalizes to `0`. The guard that catches this is in `sign_transfer`, which executes in a separate transaction after the tokens are already locked:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

When this `require!` panics, the `sign_transfer` transaction reverts, but the transfer message and locked tokens remain in contract storage. Recovery is impossible because `update_transfer_fee` enforces:

```rust
require!(
    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

The fee can only be increased, never decreased. There is no cancel or refund function for pending NEAR-origin transfers.

## Impact Explanation

A user's tokens are permanently frozen in the NEAR bridge contract. The source-chain lock succeeds and is irreversible; the destination-chain transfer can never be finalized because `sign_transfer` will always revert. This is a concrete, permanent freezing of bridged funds, matching the Critical impact scope: *permanent freezing of bridged funds across NEAR flows*.

## Likelihood Explanation

The condition is reachable by any unprivileged user via the public `ft_transfer_call` → `init_transfer` path with no special privileges. It is realistic for any token pair with a large decimal difference (e.g., 24-decimal NEAR-native tokens bridged to 6-decimal EVM tokens). A user who sets a fee of "almost one destination unit" in origin-side units may inadvertently leave a sub-unit remainder. The scenario is also reachable by a user who intentionally or accidentally miscalculates the fee. No external dependencies, oracle manipulation, or privileged access are required.

## Recommendation

Add a validation in `init_transfer` (after token decimals are available) to ensure `normalize_amount(amount - fee, decimals) > 0`. If decimals are not available at `init_transfer` time, enforce a minimum net-amount check based on the registered token decimals at the point where the `TransferMessage` is stored, or apply the same guard already present in `sign_transfer` earlier in the flow. Additionally, consider adding a cancel/refund mechanism for pending transfers to provide a recovery path for stuck funds.

## Proof of Concept

Token registered with `origin_decimals = 24`, `decimals = 6` (`diff = 18`):

1. User calls `ft_transfer_call` with `amount = 2_000_000_000_000_000_000` (2 × 10¹⁸).
2. User sets `fee = 1_000_000_000_000_000_001` (just over 10¹⁸); satisfies `fee < amount`.
3. `init_transfer` passes the fee check and locks the tokens in the bridge.
4. `amount_without_fee = 999_999_999_999_999_999` (just under 10¹⁸).
5. Relayer calls `sign_transfer`; `normalize_amount(999_999_999_999_999_999, diff=18) = 0`.
6. `require!(0 > 0, ...)` panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`; transaction reverts.
7. Transfer message remains in storage; tokens remain locked.
8. `update_transfer_fee` cannot lower the fee (`fee >= current_fee` enforced).
9. Tokens are permanently frozen with no recovery path.

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
