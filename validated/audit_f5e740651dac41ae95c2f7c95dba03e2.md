Audit Report

## Title
Missing Minimum-Amount Validation at `init_transfer` Causes Permanent Freezing of Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

## Summary
`init_transfer` locks user tokens and stores a `TransferMessage` without verifying that the net transfer amount survives decimal normalization to a non-zero value. When a trusted relayer later calls `sign_transfer`, `normalize_amount` applies floor division and returns zero, causing an unconditional panic. Because no cancel or refund path exists for a successfully stored pending transfer, the locked tokens are permanently frozen.

## Finding Description
`init_transfer` constructs the `TransferMessage` and validates only that `fee.fee < amount`: [1](#0-0) 

It then calls `init_transfer_internal`, which stores the message and locks (or burns) the full token amount: [2](#0-1) 

Later, when a trusted relayer calls `sign_transfer`, the net amount is normalized for the destination chain: [3](#0-2) 

`normalize_amount` uses integer floor division: [4](#0-3) 

For a token where `origin_decimals > decimals` (e.g., 24 on NEAR → 18 on EVM, divisor = `10^6`), any `amount_without_fee()` value less than `10^6` normalizes to zero. The `require!(amount_to_transfer > 0, ...)` guard then panics on every `sign_transfer` call for that transfer ID. The transfer message is never removed and the locked tokens are never released.

## Impact Explanation
This constitutes **permanent freezing of bridged funds** — a Critical allowed impact. Tokens are locked inside `init_transfer_internal` and remain locked indefinitely. Every subsequent `sign_transfer` call for the affected transfer ID panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`, and no cancel or user-accessible refund entry point exists for a successfully stored pending transfer.

## Likelihood Explanation
Any token registered with `origin_decimals > decimals` is affected — the common case for NEAR-native tokens bridged to EVM chains (e.g., 24 → 18). A user who sends any amount smaller than `10^(origin_decimals - decimals)` triggers the freeze. This is reachable by any unprivileged user calling `ft_transfer_call` with a small amount. No special permissions are required. The condition is a realistic user mistake (sending a dust amount) or a deliberate griefing action.

## Recommendation
Add a normalization check inside `init_transfer` (before `init_transfer_internal` is called) to reject transfers whose net amount normalizes to zero:

```rust
let amount_after_normalization = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_after_normalization > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

This mirrors the guard already present in `sign_transfer` but applies it at deposit time, before tokens are locked, so the user receives a clear rejection and their tokens are returned via the `ft_transfer_call` refund mechanism.

## Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (divisor = `10^6`).
2. User calls `ft_transfer_call` with `amount = 1` and `fee = 0`, targeting an EVM recipient.
3. `init_transfer` passes the `fee < amount` check (`0 < 1`), calls `init_transfer_internal`, which locks 1 token unit and stores the `TransferMessage`.
4. Trusted relayer calls `sign_transfer` for the stored transfer ID.
5. `normalize_amount(1 - 0, Decimals { decimals: 18, origin_decimals: 24 }) = 1 / 1_000_000 = 0`.
6. `require!(0 > 0, ...)` panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
7. The transfer message remains in `pending_transfers`; the 1-unit token balance remains locked with no recovery path.

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

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
