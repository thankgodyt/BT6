Audit Report

## Title
Permanently Locked Funds Due to `normalize_amount` Returning Zero in `sign_transfer` - (File: `near/omni-bridge/src/lib.rs`)

## Summary

`init_transfer` accepts and locks user tokens after only verifying `fee < amount`, with no check that the net amount survives decimal normalization. When `sign_transfer` later calls `normalize_amount` via floor division and the result is zero, it panics unconditionally. Because the transfer message is never removed on this panic path and no user-accessible cancel or refund path exists for outbound NEAR→EVM transfers in this state, the locked tokens are permanently frozen.

## Finding Description

**Entry point — `init_transfer` (L554–557):**
The only validation before locking tokens is:
```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
```
No downstream normalization constraint is enforced here. Tokens are locked immediately after this check passes.

**Normalization — `normalize_amount` (L2784–2787):**
```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```
This is pure floor division. For a token with `origin_decimals = 24`, `decimals = 18`, the factor is `10^6`. Any `amount_without_fee()` below `1_000_000` yields `0`.

**Finalization gate — `sign_transfer` (L475–485):**
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
This panics before the MPC signing call is ever made. The `sign_transfer_callback` is therefore never reached, so the transfer message is never removed from storage (the callback only removes it on a successful signing when `fee.is_zero()`, per L656–658). Every subsequent call to `sign_transfer` for this `transfer_id` produces the same panic.

**No recovery path:** A search across `near/**/*.rs` confirms no `cancel_transfer` function exists for outbound NEAR→EVM transfers. The one `fn refund` present in `lib.rs` handles inbound (EVM→NEAR) failed transfers, not outbound transfers stuck before MPC signing. The user has no callable path to recover the locked tokens.

## Impact Explanation

This matches the Critical impact: **permanent freezing of bridged funds**. The locked tokens (NEP-141 fungible tokens transferred into the bridge via `ft_on_transfer`) cannot be retrieved, signed over, or refunded. The bridge contract holds them indefinitely with no state transition available to the user or any unprivileged party.

## Likelihood Explanation

Any unprivileged user can trigger this by calling `ft_on_transfer` with an amount below the normalization factor for the token's decimal configuration. For NEAR-native tokens (24 decimals → 18 EVM decimals, factor = 10^6), any transfer below 1,000,000 yoctoNEAR-equivalent base units is affected. No special role, leaked key, or external dependency failure is required — only a small transfer amount. The protocol's own comment at L2781–2783 acknowledges dust locking when `fee > 0` but does not address the case where the entire net amount normalizes to zero.

## Recommendation

Add a normalization check inside `init_transfer` (or `init_transfer_internal`) before storing the transfer message and locking tokens:

```rust
let decimals = self.token_decimals.get(&token_address);
if let Some(decimals) = decimals {
    require!(
        Self::normalize_amount(
            transfer_message.amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals
        ) > 0,
        BridgeError::InvalidAmountToTransfer.as_ref()
    );
}
```

This mirrors the existing check in `sign_transfer` and enforces the downstream constraint at the entry point, preventing tokens from ever being locked in an unrecoverable state.

## Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (normalization factor = `10^6`).
2. Call `ft_on_transfer` on the NEAR bridge with `amount = 500_000`, `fee = 0`, and a valid EVM recipient. `init_transfer` succeeds — tokens are locked.
3. Have a trusted relayer call `sign_transfer` for the resulting `transfer_id`.
4. Observe panic: `ERR_INVALID_AMOUNT_TO_TRANSFER` at `near/omni-bridge/src/lib.rs` L482–485.
5. Confirm the transfer message remains in contract storage (not removed).
6. Repeat step 3 any number of times — the result is always the same panic.
7. Confirm no user-callable function exists to cancel or refund the outbound transfer.