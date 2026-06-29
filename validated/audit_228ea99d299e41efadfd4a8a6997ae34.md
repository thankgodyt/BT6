Based on my code review, the claim is technically accurate. Let me verify the key assertions:

**Confirmed facts from the code:**

1. `sign_transfer` (L471-485): Normalizes amount and panics with `ERR_INVALID_AMOUNT_TO_TRANSFER` if result is 0 — **before** the MPC call at L508. [1](#0-0) 

2. `init_transfer` (L554-557): Only checks `fee < amount`, no normalization pre-check. [2](#0-1) 

3. `normalize_amount` (L2784-2787): Floor division confirmed. The code comment at L2781-2782 explicitly states "When fee = 0, dust stays locked/burned" — acknowledging permanent loss of sub-unit amounts. [3](#0-2) 

4. No `cancel_transfer` or `refund_transfer` functions exist in the contract. `remove_transfer_message` is only called in `sign_transfer_callback` (requires successful MPC) and `claim_fee_callback` (requires finalization proof). [4](#0-3) 

5. CLAUDE.md false positive #2 covers underflow (`origin_decimals < decimals`), not the small-amount scenario. [5](#0-4) 

---

Audit Report

## Title
Permanent Freezing of Bridged Funds When Normalized Transfer Amount Rounds to Zero - (File: near/omni-bridge/src/lib.rs)

## Summary
`init_transfer` locks or burns user tokens and stores the transfer in `pending_transfers` without verifying that the net amount survives decimal normalization. When `sign_transfer` is later called, it normalizes the amount via floor division and panics if the result is zero. Because no cancel or refund path exists, and all removal paths for `pending_transfers` require a successful MPC signature that can never be produced, the user's tokens are permanently frozen.

## Finding Description

**Step 1 – Token lock/burn with no normalization pre-check**

`init_transfer` validates only that `fee < amount`:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

A transfer where `amount − fee < 10^(origin_decimals − decimals)` passes this guard. Tokens are locked or burned and the transfer is stored in `pending_transfers`.

**Step 2 – Panic in `sign_transfer` before MPC call**

When a relayer calls `sign_transfer`, the bridge normalizes the amount:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

`normalize_amount` uses floor division (`amount / 10^diff_decimals`). If `amount_without_fee < 10^(origin_decimals − decimals)`, the result is `0` and the function panics **before** the `ext_signer` MPC call at L508. No signature is ever requested.

**Step 3 – No recovery path**

`remove_transfer_message` is called in exactly two places:
- `sign_transfer_callback` — only when the MPC call succeeds (unreachable here).
- `claim_fee_callback` — requires a finalization proof derived from an MPC signature (also unreachable).

No `cancel_transfer`, `refund_transfer`, or equivalent function exists. The transfer is permanently stuck in `pending_transfers`.

The code comment on `normalize_amount` acknowledges "When fee = 0, dust stays locked/burned" but treats this as acceptable for sub-unit remainders. The vulnerability is the case where the **entire** net amount normalizes to zero, which is not a remainder but a total loss.

## Impact Explanation

Permanent freezing of bridged funds — a Critical allowed impact. User tokens are locked in the bridge contract (or burned) with no corresponding mint on the destination chain and no recovery mechanism. The impact scales with the decimal gap: for a token with `origin_decimals=6`, `decimals=0`, any transfer where `amount − fee < 1,000,000` (i.e., less than 1 full token) is permanently frozen.

## Likelihood Explanation

Reachable by any unprivileged user on any token registered with `origin_decimals > decimals` (the standard precision-reducing configuration). No special privileges are required. A user sending a fractional amount, or setting a fee that brings the net amount below the normalization threshold, triggers this inadvertently. The `init_transfer` fee check does not prevent it.

## Recommendation

Perform the normalization check inside `init_transfer`, before tokens are locked or burned, so the transaction is rejected cleanly:

```rust
// After constructing transfer_message, before init_transfer_internal:
if let Some(token_address) = self.get_token_address(
    transfer_message.get_destination_chain(),
    self.get_token_id(&transfer_message.token),
) {
    if let Some(decimals) = self.token_decimals.get(&token_address) {
        let normalized = Self::normalize_amount(
            transfer_message.amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals,
        );
        require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
    }
}
```

This fails early with a clear error and refunds the user before any state change.

## Proof of Concept

1. Register a token with `origin_decimals=6`, `decimals=0`.
2. User calls `ft_transfer_call` to the bridge with `amount=500_000`, `fee=0`.
3. `init_transfer` passes (`0 < 500_000`). 500,000 tokens are burned. Transfer stored in `pending_transfers`.
4. Relayer calls `sign_transfer`:
   - `amount_without_fee = 500_000`
   - `normalize_amount(500_000, Decimals { decimals: 0, origin_decimals: 6 }) = 500_000 / 10^6 = 0`
   - `require!(0 > 0, ...)` → panic: `ERR_INVALID_AMOUNT_TO_TRANSFER`
5. Transfer remains in `pending_transfers` indefinitely. User's 500,000 tokens are permanently lost.

A unit test can reproduce this by calling `init_transfer_internal` with the above parameters, then calling `sign_transfer` and asserting the panic, then confirming the transfer still exists in `pending_transfers` with no removal path available.

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

**File:** near/CLAUDE.md (L192-195)
```markdown
**2. Decimal Arithmetic Underflow (NOT a vulnerability)**
- Design expects `origin_decimals >= decimals` (normalization to lower precision)
- Workspace has `overflow-checks = true` in Cargo.toml
- Misconfiguration causes panic (correct fail-safe), not silent corruption
```
