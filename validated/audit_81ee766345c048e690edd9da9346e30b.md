Audit Report

## Title
Missing Normalized-Amount Guard in `init_transfer` Causes Permanent Token Loss - (File: near/omni-bridge/src/lib.rs)

## Summary
The NEAR `omni-bridge` contract accepts an outbound transfer via `ft_transfer_call` → `init_transfer` → `init_transfer_internal` and immediately burns or locks the user's tokens without verifying that the post-fee amount survives decimal normalization. When the normalized amount floors to zero, the tokens are permanently destroyed, the `TransferMessage` is orphaned in storage, and no on-chain path exists to refund or cancel the transfer.

## Finding Description
The exploit path is a three-step gap:

**Step 1 — `init_transfer` validates only `fee < amount`** (L554-557). No check is made that `amount - fee` is representable on the destination chain. [1](#0-0) 

**Step 2 — `init_transfer_internal` burns/locks the full amount** (L1850-1857) and stores the `TransferMessage` before any normalization is attempted. [2](#0-1) 

**Step 3 — The normalization guard lives only in `sign_transfer`** (L475-485), called later by a trusted relayer. `normalize_amount` uses floor division (L2784-2786), so any `amount_without_fee < 10^(origin_decimals − decimals)` produces zero and causes `sign_transfer` to panic. [3](#0-2) [4](#0-3) 

**No recovery path.** `sign_transfer_callback` only calls `remove_transfer_message` when the MPC call *succeeds* and `fee.is_zero()` (L655-658). A panicking `sign_transfer` never reaches the callback, so the record is permanently orphaned and the burned/locked tokens are unrecoverable. [5](#0-4) 

The `normalize_amount` docstring (L2781-2782) acknowledges "dust stays locked/burned" for the floor-division remainder, but this is distinct from the scenario where the *entire* transfer amount normalizes to zero — a complete, unrecoverable loss rather than a rounding residual. [6](#0-5) 

## Impact Explanation
This is a concrete instance of **permanent freezing / loss of bridged funds** and **decimal/normalization abuse that changes user balances** — both listed Critical impacts. A user's tokens are irreversibly burned or locked on NEAR with zero possibility of recovery or cancellation. The protocol emits an `InitTransferEvent` log, giving false confidence that the transfer is progressing.

## Likelihood Explanation
Any unprivileged user can trigger this via the standard `ft_transfer_call` public entry point — no special role or leaked key is required. Tokens with large decimal differences (e.g., NEAR native 24 decimals → EVM 18 decimals, threshold = 1,000,000 units) are already deployed on mainnet. Triggering conditions include: a user sending a "dust" amount, a UI rounding error, or a programmatic transfer computing a small residual after fee subtraction. The `fee < amount` guard passes silently for any nonzero fee below the threshold, making the failure invisible at initiation time.

## Recommendation
Add a normalization check inside `init_transfer_internal` (or at the end of `init_transfer`) **before** burning or locking tokens:

```rust
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee()
        .near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This mirrors the guard already present in `sign_transfer` (L482-485) but moves it to the point where the user's funds are still safe and the transaction can revert cleanly. [7](#0-6) 

## Proof of Concept
**Setup:** Token registered with `origin_decimals = 24`, `decimals = 18` (diff = 6, threshold = 1,000,000 units).

```
User calls ft_transfer_call:
  amount = 500_000          // < 1_000_000 threshold
  fee    = 0                // fee (0) < amount (500_000) → passes init_transfer guard

init_transfer_internal (L1850-1857):
  burn_tokens_if_needed(token, 500_000)   // tokens destroyed on NEAR
  lock_tokens_if_needed(...)              // locked in bridge escrow
  store TransferMessage                   // stored permanently
  emit InitTransferEvent                  // false-positive success log
  return U128(0)                          // ft_transfer_call keeps tokens

Relayer calls sign_transfer (L447):
  amount_without_fee = 500_000
  normalize_amount(500_000, {24,18})
    = 500_000 / 10^6 = 0                 // floor division
  require!(0 > 0) → PANIC "ERR_INVALID_AMOUNT_TO_TRANSFER"

sign_transfer_callback: never reached
remove_transfer_message: never called

Result:
  - 500_000 tokens burned/locked permanently
  - TransferMessage orphaned in storage
  - No refund, no cancel, no completion possible
```

A local integration test can reproduce this by registering a token with the above decimal configuration, calling `ft_transfer_call` with `amount = 500_000` and `fee = 0`, asserting the contract returns `U128(0)` (tokens consumed), then calling `sign_transfer` and asserting it panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`, and finally confirming the transfer message remains in storage with no mint or unlock having occurred.

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
