Audit Report

## Title
Floor Division in `normalize_amount` Can Produce Zero Transfer Amount, Permanently Locking/Burning User Tokens - (File: `near/omni-bridge/src/lib.rs`)

## Summary

`normalize_amount` uses integer floor division to scale token amounts to the bridge's internal precision. When a user initiates a transfer with a net amount (after fee) smaller than `10^(origin_decimals - decimals)`, the normalized result is zero. By this point, `init_transfer_internal` has already irreversibly burned or locked the user's tokens, and `sign_transfer` will always panic with `InvalidAmountToTransfer`, leaving the transfer permanently stuck with no recovery path.

## Finding Description

`normalize_amount` performs floor division:

```rust
// near/omni-bridge/src/lib.rs L2784-2787
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

In `sign_transfer`, the normalized value is checked after the fact:

```rust
// near/omni-bridge/src/lib.rs L475-485
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
``` [2](#0-1) 

However, `init_transfer_internal` burns or locks the full token amount **before** any normalization check is ever performed:

```rust
// near/omni-bridge/src/lib.rs L1850-1857
if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
    self.lock_tokens_if_needed(
        transfer_message.get_destination_chain(),
        &token_id,
        transfer_message.amount.0,
    );
}
``` [3](#0-2) 

The only guard at `init_transfer` time is `fee < amount`:

```rust
// near/omni-bridge/src/lib.rs L554-557
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [4](#0-3) 

There is no check that `normalize_amount(amount - fee) > 0` before the irreversible burn/lock. The `remove_transfer_message` call in `sign_transfer_callback` is only reachable after MPC signing succeeds:

```rust
// near/omni-bridge/src/lib.rs L655-658
if let Ok(signature) = call_result {
    if fee.is_zero() {
        self.remove_transfer_message(message_payload.transfer_id);
    }
``` [5](#0-4) 

Since `sign_transfer` panics before reaching the MPC call, `sign_transfer_callback` is never invoked, and no public cancel or refund function exists. The transfer record remains in `pending_transfers` indefinitely.

## Impact Explanation

This constitutes **permanent freezing of bridged funds**, matching the Critical allowed impact: *"permanent freezing of bridged funds across NEAR, EVM, Solana, Starknet, Bitcoin, Zcash, or Wormhole-routed flows."* Any user who sends a token amount (after fee) below the normalization threshold has their tokens irreversibly burned or locked in the bridge contract with no recovery path. For tokens with `origin_decimals = 24` and `decimals = 18` (diff = 6), any net transfer below `1,000,000` base units triggers this. The protocol's own comment at line 2781 acknowledges floor division but only addresses sub-unit dust, not the case where the entire net amount normalizes to zero. [6](#0-5) 

## Likelihood Explanation

Any unprivileged user can trigger this by calling `ft_transfer_call` with a small token amount targeting a chain where `origin_decimals` significantly exceeds `decimals`. No special permissions, coordination, or privileged access are required for the user-side action. The relayer calling `sign_transfer` is a normal protocol flow. High-precision tokens (e.g., 24-decimal NEAR tokens bridged to 18-decimal EVM representations) are a realistic and common configuration. The condition is easy to satisfy accidentally (e.g., a user sending a "dust" amount) or deliberately.

## Recommendation

Add a normalization check in `init_transfer` (or `init_transfer_internal`) **before** tokens are burned or locked:

```rust
let token_address = self.get_token_address(
    transfer_message.get_destination_chain(),
    self.get_token_id(&OmniAddress::Near(token_id.clone())),
).near_expect(BridgeError::FailedToGetTokenAddress);

let decimals = self.token_decimals.get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);

let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This mirrors the existing check in `sign_transfer` but places it before any irreversible state change, causing the transaction to revert and returning the tokens to the user.

## Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (divisor = `1_000_000`).
2. User calls `ft_transfer_call` sending `500_000` base units with `fee = 0`.
3. `init_transfer_internal` burns/locks `500_000` tokens and stores the transfer in `pending_transfers`.
4. Relayer calls `sign_transfer` for the transfer ID.
5. `normalize_amount(500_000, decimals)` = `500_000 / 1_000_000` = `0` (floor division).
6. `require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer)` panics.
7. MPC signing is never reached; `sign_transfer_callback` is never called; `remove_transfer_message` is never called.
8. The `500_000` tokens are permanently burned/locked; the transfer record is permanently stuck in `pending_transfers`.

A local unit test can reproduce this by constructing a `TransferMessage` with `amount = U128(500_000)`, `fee = U128(0)`, registering token decimals with `origin_decimals = 24` and `decimals = 18`, calling `init_transfer_internal`, then calling `sign_transfer` and asserting it panics with `InvalidAmountToTransfer` while the transfer remains in storage.

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
