Audit Report

## Title
Permanent Fund Loss When `normalize_amount` Returns Zero in `sign_transfer` After Tokens Are Already Burned/Locked — (File: `near/omni-bridge/src/lib.rs`)

## Summary
When a user initiates a NEAR-to-foreign-chain transfer with an amount (minus fee) below the decimal normalization divisor, `normalize_amount` returns zero via floor division. Tokens are irreversibly burned or locked inside `init_transfer_internal` before this zero-amount check is ever reached in `sign_transfer`, which then panics. The transfer remains permanently stuck in `pending_transfers` with no on-chain recovery path.

## Finding Description
The `normalize_amount` function at L2784–2787 uses floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

If `amount < 10^(origin_decimals - decimals)`, the result is `0`.

The zero-amount guard lives exclusively in `sign_transfer` at L475–485:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

However, by the time `sign_transfer` is called, `init_transfer_internal` (L1850–1857) has already irreversibly consumed the tokens:

```rust
if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
    self.lock_tokens_if_needed(
        transfer_message.get_destination_chain(),
        &token_id,
        transfer_message.amount.0,
    );
}
```

The only pre-burn validation in `init_transfer` (L554–557) is:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

There is no check that `normalize_amount(amount - fee, decimals) > 0` before the irreversible burn/lock step. The `remove_transfer_message_without_refund` call inside `init_transfer_internal` (L1846) only fires on storage-balance failure, not on a subsequent `sign_transfer` panic. No public cancel or refund function exists to recover a transfer that is stuck after burning.

Notably, the `normalize_amount` docstring at L2781–2783 explicitly acknowledges: *"When fee = 0, dust stays locked/burned."* This confirms the behavior is real, but the comment addresses sub-unit remainder dust, not the case where the entire post-fee amount normalizes to zero — a qualitatively different and more severe outcome.

## Impact Explanation
This directly matches the Critical impact class: **permanent freezing of bridged funds**. A user's tokens are burned on NEAR with no mechanism to complete the transfer (since `sign_transfer` will always panic for this transfer ID) and no mechanism to recover the burned tokens. The funds are permanently destroyed.

## Likelihood Explanation
Any token pair where `origin_decimals > decimals` (e.g., a NEAR-native token with 24 decimals bridged to an EVM representation with 18 decimals, giving a divisor of 10^6) creates this condition. Any unprivileged token holder who sends fewer than `10^(origin_decimals - decimals)` base units triggers the bug through the standard public `ft_transfer_call` → `init_transfer` flow. No special access, no front-running, no collusion required. "Dust" amounts are a realistic user scenario, especially for automated or programmatic senders.

## Recommendation
Add the normalization check inside `init_transfer`, before `init_transfer_internal` is called and before any tokens are burned or locked:

```rust
let token_address = self.get_token_address(
    init_transfer_msg.get_destination_chain(),
    token_id.clone(),
).near_expect(BridgeError::FailedToGetTokenAddress);

let decimals = self.token_decimals
    .get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);

let normalized = Self::normalize_amount(
    amount.0 - init_transfer_msg.fee.0,
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This mirrors the guard already present in `sign_transfer` but places it before the irreversible token consumption step, allowing `ft_transfer_call` to refund the tokens to the sender.

## Proof of Concept
1. Register a token with `origin_decimals = 24`, `decimals = 18` (divisor = `10^6`).
2. User calls `ft_transfer_call` with `amount = 500_000` and `fee = 0`.
3. `init_transfer` passes the only guard (`fee < amount` → `0 < 500_000` ✓).
4. `init_transfer_internal` is reached: `burn_tokens_if_needed` burns `500_000` units; transfer message stored in `pending_transfers`.
5. Trusted relayer calls `sign_transfer` for this transfer ID.
6. `normalize_amount(500_000, Decimals { decimals: 18, origin_decimals: 24 })` → `500_000 / 1_000_000 = 0`.
7. `require!(amount_to_transfer > 0, ...)` panics — transaction reverts.
8. Transfer message remains in `pending_transfers` indefinitely; `500_000` units are permanently burned with no recovery path. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** near/omni-bridge/src/lib.rs (L1844-1848)
```rust
            .is_err()
        {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }
```

**File:** near/omni-bridge/src/lib.rs (L1850-1857)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
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
