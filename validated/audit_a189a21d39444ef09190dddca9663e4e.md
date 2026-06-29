Audit Report

## Title
Permanent Locking of User Funds via Zero-Normalized Amount Check in `sign_transfer` — (File: `near/omni-bridge/src/lib.rs`)

## Summary

`init_transfer` only validates `fee < amount` before locking tokens and storing the transfer message. When `amount - fee` is a positive integer smaller than `10^(origin_decimals - decimals)`, the floor division in `normalize_amount` produces zero, causing `sign_transfer` to always panic at the `require!(amount_to_transfer > 0, ...)` guard. Because `update_transfer_fee` only permits fee increases and no cancel/refund entrypoint exists, the locked tokens are irrecoverable without admin intervention.

## Finding Description

**Root cause — missing pre-lock normalization check in `init_transfer`:**

`init_transfer` stores the transfer message after only checking `fee.fee < amount`: [1](#0-0) 

No check is made that the normalized net amount (`(amount - fee) / 10^diff_decimals`) is greater than zero. Tokens are locked at this point.

**Normalization uses floor division:** [2](#0-1) 

When `amount_without_fee < 10^diff_decimals`, the result is `0`.

**`sign_transfer` panics on zero:** [3](#0-2) 

This panic is permanent — the transfer message remains in `pending_transfers` and tokens remain locked.

**`update_transfer_fee` only allows fee increases:** [4](#0-3) 

Increasing the fee makes `amount_without_fee` even smaller, keeping the normalized amount at zero. There is no path to decrease the fee or cancel the transfer.

**`amount_without_fee` is a simple subtraction:** [5](#0-4) 

## Impact Explanation

This is a **permanent freezing of bridged funds**, matching the Critical impact scope. A user whose transfer enters this state has no on-chain recourse: `sign_transfer` always panics, `update_transfer_fee` cannot reduce the fee, and no cancel/refund entrypoint exists. The locked tokens are irrecoverable without privileged admin action. The code comment at line 2781 acknowledges that dust "stays locked/burned" when fee is zero, but does not address the case where the entire net amount normalizes to zero. [6](#0-5) 

## Likelihood Explanation

Any token whose NEAR-side decimals exceed the destination chain's registered decimals (e.g., 24 NEAR decimals → 18 EVM decimals, `diff_decimals = 6`) is affected. A user who sets a fee leaving `amount - fee` in the range `[1, 999_999]` triggers the condition. This can occur accidentally (user unaware of decimal scaling) or via a contract initiating transfers on behalf of users with an adversarially chosen fee. The `init_transfer` validation does not prevent it.

## Recommendation

Add the normalized-amount check at `init_transfer` time, before tokens are locked:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

This mirrors the existing guard in `sign_transfer` but fires before the transfer is stored, allowing the transaction to revert cleanly and tokens to be returned to the sender. Alternatively, add a cancel/refund entrypoint for pending transfers.

## Proof of Concept

1. Register a NEAR token on an EVM chain with `origin_decimals = 24`, `decimals = 18` (`diff_decimals = 6`).
2. Call `ft_transfer_call` → `init_transfer` with `amount = 2_000_000`, `fee = 1_999_999`. The check `fee < amount` passes; tokens are locked; transfer message is stored.
3. Call `sign_transfer` for this transfer:
   - `amount_without_fee() = 1`
   - `normalize_amount(1, diff=6) = 1 / 1_000_000 = 0`
   - `require!(0 > 0, ...)` → **panic: `ERR_INVALID_AMOUNT_TO_TRANSFER`**
4. Call `update_transfer_fee` with any higher fee — `amount_without_fee` becomes 0 or stays below `10^6`, still normalizes to 0.
5. No other entrypoint removes the transfer message or returns the tokens. Funds are permanently locked.

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

**File:** near/omni-types/src/lib.rs (L593-595)
```rust
    pub fn amount_without_fee(&self) -> Option<u128> {
        self.amount.0.checked_sub(self.fee.fee.0)
    }
```
