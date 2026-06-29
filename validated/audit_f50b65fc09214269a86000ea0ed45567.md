Audit Report

## Title
Transfer Permanently Stuck When Normalized Amount Rounds to Zero — (`near/omni-bridge/src/lib.rs`)

## Summary

`init_transfer` burns or locks user tokens and stores the transfer in `pending_transfers` without verifying that `normalize_amount(amount_without_fee) > 0`. `sign_transfer` enforces this check after the fact, causing every subsequent relayer call to panic unconditionally. Because the MPC signing call is never reached, neither `sign_transfer_callback` nor `claim_fee_callback` is ever invoked, so `remove_transfer_message` is never called and the burned/locked funds are permanently unrecoverable.

## Finding Description

**Phase 1 — `init_transfer` (L523–619):** The only amount validation is `transfer_message.fee.fee < transfer_message.amount` at L554–557. No normalization check is performed. The function proceeds to call `init_transfer_internal`, which burns (for bridge-deployed tokens) or locks (for native tokens) the user's funds, and stores the `TransferMessage` in `pending_transfers`. [1](#0-0) 

**Phase 2 — `sign_transfer` (L447–521):** After retrieving the stored transfer, the function calls `normalize_amount` and then enforces `amount_to_transfer > 0`: [2](#0-1) 

**`normalize_amount` uses floor division (L2784–2787):** [3](#0-2) 

For any token where `origin_decimals > decimals` (e.g., 24 vs 18, divisor = 10^6), any `amount_without_fee < 10^6` normalizes to zero. The `require!` at L482 panics on every future call to `sign_transfer` for that transfer ID.

**No recovery path:** `remove_transfer_message` inside `sign_transfer_callback` is only reached when the MPC signing call succeeds: [4](#0-3) 

Since `sign_transfer` panics at L482 before the MPC `ext_signer::ext(...).sign(...)` call at L508 is ever made, `sign_transfer_callback` is never scheduled. The transfer record stays in `pending_transfers` forever.

The inline comment at L2781–2783 acknowledges floor-division dust for remainders but does not address the case where the entire `amount_without_fee` normalizes to zero — a categorically different and more severe outcome. [5](#0-4) 

## Impact Explanation

For bridge-deployed tokens, the token is **burned** on NEAR in `init_transfer_internal` before `sign_transfer` is ever called. The corresponding mint on the destination chain never happens — permanent, total loss of the transferred amount. For native NEAR-origin tokens, the amount is **locked** in the bridge contract with no unlock path — permanent freezing of bridged funds. This matches the Critical allowed impact: *"permanent freezing of bridged funds"* and *"decimal/normalization abuse... that changes user or protocol balances."*

## Likelihood Explanation

Any token registered with `origin_decimals > decimals` (a standard configuration) is affected. A user sending fewer than `10^(origin_decimals - decimals)` units triggers the bug. The entry point is the standard NEP-141 `ft_transfer_call`, callable by any token holder with no special privileges. The condition can be triggered accidentally (small or dust transfers) or deliberately by a griefing attacker causing other users to lose funds.

## Recommendation

Add the normalization check inside `init_transfer` before `init_transfer_internal` is called, mirroring the guard already present in `sign_transfer`:

```rust
let decimals = self.token_decimals.get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This must be placed after the `TransferMessage` is constructed and the fee check passes, but **before** `init_transfer_internal` is called, so that tokens are never burned/locked for a transfer that can never be signed.

## Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (divisor = 10^6).
2. User calls `ft_transfer_call` sending `amount = 500_000` units with `fee = 0`.
3. `ft_on_transfer` → `init_transfer`: check `0 < 500_000` passes at L554; tokens are burned; transfer stored in `pending_transfers`.
4. Relayer calls `sign_transfer`: `normalize_amount(500_000, {24, 18}) = 500_000 / 1_000_000 = 0`; `require!(0 > 0)` panics at L482–485.
5. No MPC call is made; `sign_transfer_callback` is never reached; `remove_transfer_message` is never called.
6. The transfer is permanently stuck; the 500,000 burned tokens are unrecoverable.

A local integration test can reproduce this by deploying a mock token with the above decimal configuration, calling `ft_transfer_call` with `amount = 500_000`, and asserting that subsequent calls to `sign_transfer` always panic while `pending_transfers` retains the entry indefinitely.

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
