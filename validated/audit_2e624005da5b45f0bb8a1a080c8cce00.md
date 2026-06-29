Audit Report

## Title
Permanent Fund Loss When `normalize_amount` Returns Zero in `sign_transfer` After Tokens Are Already Burned/Locked — (File: `near/omni-bridge/src/lib.rs`)

## Summary

When a user initiates a NEAR-to-foreign-chain transfer with an amount (minus fee) below the decimal normalization divisor, `normalize_amount` returns `0`. Tokens are irreversibly burned or locked inside `init_transfer_internal` before this check occurs. When a trusted relayer subsequently calls `sign_transfer`, the `require!(amount_to_transfer > 0, ...)` guard panics, the transfer remains permanently in `pending_transfers`, and no cancel or refund path exists. The user's tokens are permanently lost.

## Finding Description

**Root cause:** The zero-normalized-amount guard in `sign_transfer` fires after the irreversible token burn/lock in `init_transfer_internal`.

**Code path:**

1. User calls `ft_transfer_call` → `init_transfer`. The only amount validation is: [1](#0-0) 
   This only ensures `fee < amount`; it does not check that `normalize_amount(amount - fee, decimals) > 0`.

2. `init_transfer_internal` is called. Tokens are burned or locked unconditionally: [2](#0-1) 

3. The transfer message is stored in `pending_transfers`. The function returns `U128(0)` (no refund to the caller): [3](#0-2) 

4. A trusted relayer calls `sign_transfer`. Only here is the normalization check performed: [4](#0-3) 

5. `normalize_amount` uses floor division: [5](#0-4) 
   If `amount - fee < 10^(origin_decimals - decimals)`, the result is `0` and `sign_transfer` panics every time it is called for this transfer.

6. `sign_transfer_callback` only calls `remove_transfer_message` on a *successful* MPC signing response: [6](#0-5) 
   A panicking `sign_transfer` never reaches the callback, so the transfer message is never removed.

**Why existing checks fail:** The `fee < amount` guard in `init_transfer` does not account for normalization. No public cancel or refund function exists for stuck `pending_transfers` entries. The `normalize_amount` comment acknowledges "dust stays locked/burned" for remainders, but does not address the case where the *entire* amount normalizes to zero, causing `sign_transfer` to be permanently unexecutable. [7](#0-6) 

## Impact Explanation

This is **permanent freezing and loss of bridged funds** — a Critical impact under the allowed scope. Burned tokens on NEAR are destroyed with no recovery path. Locked tokens remain locked with no mechanism to release them back to the user. The transfer is permanently stuck in `pending_transfers` because `sign_transfer` will always panic for that transfer ID, and no cancel/refund function is available to the user or relayer.

## Likelihood Explanation

Any token pair where `origin_decimals > decimals` (e.g., a NEAR-native token with 24 decimals bridged to an EVM representation with 18 decimals, giving a divisor of `10^6`) creates this condition. Any token holder can trigger it by calling `ft_transfer_call` with an amount below the divisor threshold. No privileged access is required. The entry point is the standard public bridge flow. A user unfamiliar with decimal normalization, or one sending a "dust" amount, can trigger this without any attacker involvement — the user is the victim of their own valid-looking transaction.

## Recommendation

Add a normalization check in `init_transfer` (or at the start of `init_transfer_internal`) **before** `burn_tokens_if_needed` / `lock_tokens_if_needed` is called:

```rust
let token_address = self.get_token_address(
    transfer_message.get_destination_chain(),
    self.get_token_id(&transfer_message.token),
).near_expect(BridgeError::FailedToGetTokenAddress);

let decimals = self.token_decimals
    .get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);

let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee()
        .near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This mirrors the guard already present in `sign_transfer` but places it before the irreversible token consumption step, allowing `ft_transfer_call` to return the full amount to the caller as a refund.

## Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (divisor = `10^6`).
2. User calls `ft_transfer_call` with `amount = 500_000` (below `10^6`) and `fee = 0`.
3. `init_transfer` passes the `fee < amount` check (`0 < 500_000`). ✓
4. `init_transfer_internal` is reached: `burn_tokens_if_needed` burns `500_000` units from the user.
5. Transfer message is stored in `pending_transfers` with `origin_nonce = N`.
6. `init_transfer_internal` returns `U128(0)` — no refund issued.
7. Trusted relayer calls `sign_transfer(transfer_id: N, ...)`.
8. `normalize_amount(500_000, Decimals { decimals: 18, origin_decimals: 24 })` → `500_000 / 1_000_000 = 0`.
9. `require!(0 > 0, ...)` panics — transaction aborted, no state changes.
10. Steps 7–9 repeat identically on every future `sign_transfer` call for this transfer ID.
11. Transfer message remains in `pending_transfers` forever; user's `500_000` units are permanently burned with no recovery path.

**Test plan:** Write a NEAR sandbox integration test that (a) deploys the bridge with a token registered at `origin_decimals=24, decimals=18`, (b) calls `ft_transfer_call` with `amount=500_000`, (c) asserts the token balance decreased by `500_000`, (d) calls `sign_transfer` as a trusted relayer and asserts it panics with `InvalidAmountToTransfer`, (e) asserts the transfer message still exists in `pending_transfers`, and (f) asserts no refund was issued.

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

**File:** near/omni-bridge/src/lib.rs (L1863-1864)
```rust
        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
        U128(0)
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
