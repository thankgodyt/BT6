Audit Report

## Title
Sub-unit transfer amount permanently freezes user funds due to missing normalization pre-check in `init_transfer_internal` - (File: near/omni-bridge/src/lib.rs)

## Summary
When a user initiates a NEAR → Foreign chain transfer with `amount_without_fee < 10^(origin_decimals - decimals)`, `normalize_amount` returns 0 via floor division. The `require!(amount_to_transfer > 0)` guard in `sign_transfer()` then permanently blocks MPC signing. Because `init_transfer_internal` already burned or locked the user's tokens before this check is ever reached, and no public cancel or refund path exists for pending transfers, the funds are irrecoverably lost.

## Finding Description

`sign_transfer()` at L475–485 normalizes `amount_without_fee` before requesting an MPC signature:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

`normalize_amount` at L2784–2787 uses floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

Any `amount_without_fee < 10^(origin_decimals - decimals)` produces 0, causing `sign_transfer()` to panic on every invocation for that transfer.

The critical gap is in `init_transfer_internal` at L1829–1865: it stores the transfer, burns or locks the user's tokens, and emits `InitTransferEvent` — all **before** any normalization check:

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(...);
// ...
env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
U128(0)
```

The only early-return paths in `init_transfer_internal` are: (1) insufficient storage balance (refunds before burning), and (2) non-NEAR token address (refunds before burning). Neither covers the normalization-to-zero case.

`remove_transfer_message` is a private function called only from `sign_transfer_callback` and `claim_fee_callback` — neither of which is reachable when `sign_transfer()` always panics. No public `cancel_transfer` function exists.

`update_transfer_fee` at L399–401 enforces `fee.fee >= current_fee.fee`, meaning the fee can only be increased, not decreased. Even setting `fee = amount - 1` leaves `amount_without_fee = 1`, which still normalizes to 0 for large decimal gaps (e.g., `origin_decimals=24`, `decimals=6` → scaling factor `10^18`).

## Impact Explanation

**Critical — permanent freezing of bridged funds.** Any user who initiates a NEAR → Foreign transfer where `amount_without_fee < 10^(origin_decimals - decimals)` will have their tokens permanently burned or locked inside the bridge with no recovery path. The transfer entry remains in `pending_transfers` indefinitely, and `sign_transfer()` reverts on every call. This matches the allowed impact: *permanent freezing of bridged funds across NEAR, EVM, Solana, Starknet, Bitcoin, Zcash, or Wormhole-routed flows.*

## Likelihood Explanation

**Moderate.** The decimal gap is largest for tokens with high NEAR-side precision bridging to low-precision destination chains. For a token registered with `origin_decimals = 24` and `decimals = 6` (a common USDC-like configuration), the scaling factor is `10^18`. Any transfer of less than one full destination-chain unit (e.g., less than 1 USDC-equivalent) triggers the bug. The entry point (`ft_transfer_call` → `ft_on_transfer` → `init_transfer` → `init_transfer_internal`) is fully public and requires no special role. Users unfamiliar with decimal normalization, or those who set a fee close to their transfer amount, can easily fall into this trap.

## Recommendation

Add a normalization pre-check inside `init_transfer_internal` (or in the `init_transfer` wrapper before calling it). If the normalized `amount_without_fee` is zero, return the full token amount as a refund instead of burning/locking:

```rust
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
if normalized == 0 {
    return transfer_message.amount; // refund to sender
}
```

This mirrors the existing pattern used when storage balance is insufficient in `init_transfer_internal` (L1846–1848), where `remove_transfer_message_without_refund` is called and the amount is returned before any token burning occurs.

## Proof of Concept

1. Token is registered with `origin_decimals = 24`, `decimals = 6`; scaling factor = `10^18`.
2. User calls `ft_transfer_call` on the token contract, sending `amount = 5 × 10^17` to the bridge with `fee = 0`.
3. `init_transfer_internal` stores the transfer in `pending_transfers`, burns `5 × 10^17` tokens, and emits `InitTransferEvent`. No normalization check occurs here.
4. A trusted relayer calls `sign_transfer()`:
   - `amount_without_fee() = 5 × 10^17`
   - `normalize_amount(5 × 10^17, {decimals: 6, origin_decimals: 24}) = 5 × 10^17 / 10^18 = 0`
   - `require!(0 > 0, ERR_INVALID_AMOUNT_TO_TRANSFER)` → **panics**
5. Every subsequent call to `sign_transfer()` for this transfer ID panics identically.
6. `update_transfer_fee` cannot rescue the transfer: increasing the fee to `amount - 1` leaves `amount_without_fee = 1`, which still normalizes to 0.
7. The user's `5 × 10^17` tokens are permanently burned; the transfer entry is permanently stuck in `pending_transfers` with no refund path.

A local integration test can reproduce this by: registering a token with the described decimal configuration, calling `ft_transfer_call` with a sub-unit amount, then asserting that `sign_transfer` always panics and that no public function can recover the tokens.