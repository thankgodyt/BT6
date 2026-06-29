Audit Report

## Title
No Minimum Transfer Amount Validation Causes Permanent Token Lock for Sub-Unit Transfers — (File: `near/omni-bridge/src/lib.rs`)

## Summary

`init_transfer` accepts and stores outbound transfers without verifying that the net amount survives decimal normalization to the destination chain. When `(amount - fee) < 10^(origin_decimals - decimals)`, `normalize_amount` returns `0`, causing `sign_transfer` to panic unconditionally. No cancellation path exists, so the user's tokens are permanently locked in the bridge contract.

## Finding Description

**Root cause — missing normalization guard in `init_transfer`:**

`init_transfer` stores the transfer after a single fee check: [1](#0-0) 

No check is made that `normalize_amount(amount - fee, decimals) > 0`. The transfer is written to `pending_transfers` and the user's tokens are escrowed.

**Panic in `sign_transfer`:**

When a relayer later calls `sign_transfer`, normalization is applied: [2](#0-1) 

`normalize_amount` uses floor division: [3](#0-2) 

If `amount - fee < 10^(origin_decimals - decimals)`, the result is `0` and the `require!` at L482–484 panics. The MPC signer is never called, `sign_transfer_callback` is never reached, and the transfer is never removed from `pending_transfers`.

**No recovery path:**

- `sign_transfer_callback` only removes the transfer when `fee.is_zero()`, but it is unreachable because `sign_transfer` panics before the MPC call. [4](#0-3) 
- `claim_fee` requires a destination-chain finalization proof, which never exists for a transfer that was never signed.
- `update_transfer_fee` can only increase the fee up to `amount - 1` (strict less-than), so `amount_without_fee` can be reduced to `1` but `normalize_amount(1) = 0` still panics. [5](#0-4) 
- No `cancel_transfer` or admin-rescue function exists.

**Note on the existing code comment:** The `normalize_amount` function carries a doc comment acknowledging that "dust stays locked/burned" when `fee = 0`. [6](#0-5)  However, that comment describes sub-unit *remainders* after a successful normalization (e.g., 1 unit out of 1,000,001). The claim here is categorically different: the *entire* net transfer amount normalizes to `0`, making the transfer permanently unprocessable and the full escrowed amount irrecoverable.

## Impact Explanation

This is a **permanent freezing of bridged funds**, matching the critical impact scope. Any user who initiates an outbound transfer where `(amount - fee) < 10^(origin_decimals - decimals)` loses their entire escrowed amount with no on-chain recovery path. The tokens remain locked in the bridge contract indefinitely.

## Likelihood Explanation

Tokens with a large decimal gap are common (e.g., NEAR-native tokens with 24 decimals bridged to EVM chains with 18 decimals, giving a divisor of `1,000,000`). Any user sending fewer than `1,000,000` base units triggers the bug. No special privileges are required — any unprivileged user can trigger this via `ft_transfer_call`. The scenario is realistic for low-value or dust transfers and requires no attacker; a normal user mistake suffices.

## Recommendation

Add a normalization check inside `init_transfer` (or `init_transfer_internal`) before storing the transfer. This requires looking up token decimals at `init_transfer` time, as `sign_transfer` already does:

```rust
require!(
    Self::normalize_amount(
        transfer_message.amount.0.checked_sub(transfer_message.fee.fee.0)
            .near_expect(BridgeError::InvalidFee),
        decimals
    ) > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

Alternatively, add a `cancel_transfer` function that allows the original sender to reclaim tokens from a transfer that has never been signed, providing a recovery path for already-stuck transfers.

## Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (divisor = `1,000,000`).
2. Call `ft_transfer_call` with `amount = 500_000`, `fee = 0`.
3. `init_transfer` passes: `0 < 500_000` ✓. Transfer stored; 500,000 tokens locked.
4. Relayer calls `sign_transfer(transfer_id, None, None)`.
5. `normalize_amount(500_000, {origin: 24, decimals: 18}) = 500_000 / 1_000_000 = 0`.
6. `require!(0 > 0, BridgeError::InvalidAmountToTransfer)` panics. [7](#0-6) 
7. No MPC call is made. `sign_transfer_callback` is never reached. Transfer remains in `pending_transfers` indefinitely.
8. `claim_fee` cannot be called (no destination-chain finalization proof exists).
9. User's 500,000 tokens are permanently locked with no recovery path.

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
