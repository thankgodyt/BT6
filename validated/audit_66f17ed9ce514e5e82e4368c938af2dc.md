### Title
Missing Minimum Transfer Amount Validation Causes Permanent Fund Freezing via Decimal Normalization Truncation - (File: `near/omni-bridge/src/lib.rs`)

### Summary

The `init_transfer` function on NEAR accepts any `fee` value satisfying `fee < amount`, but does not enforce that `amount - fee` (i.e., `amount_without_fee`) meets the minimum threshold imposed by decimal normalization. When `amount_without_fee` is smaller than the normalization divisor `10^(origin_decimals - decimals)`, the `normalize_amount` floor-division truncates it to zero. The subsequent `sign_transfer` call then permanently panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`, and because no cancel or refund path exists for pending transfers, the user's tokens are irreversibly locked or burned.

### Finding Description

`init_transfer` in `near/omni-bridge/src/lib.rs` validates only one constraint on the fee:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [1](#0-0) 

This allows `fee = amount - 1`, leaving `amount_without_fee = 1`. The transfer is accepted, tokens are locked or burned, and the transfer message is stored in `pending_transfers`.

Later, when a relayer calls `sign_transfer`, the bridge computes the normalized amount to send to the destination chain:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
``` [2](#0-1) 

`normalize_amount` uses floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [3](#0-2) 

For a NEAR-native token with `origin_decimals = 24` bridging to an EVM chain with `decimals = 18`, the divisor is `10^6`. Any `amount_without_fee < 10^6` normalizes to `0`, causing `sign_transfer` to panic unconditionally.

The `sign_transfer_callback` only removes the transfer message when `fee.is_zero()`:

```rust
if let Ok(signature) = call_result {
    if fee.is_zero() {
        self.remove_transfer_message(message_payload.transfer_id);
    }
    ...
}
``` [4](#0-3) 

Because `sign_transfer` panics before the MPC call is even made, the callback is never reached. The transfer message remains in `pending_transfers` indefinitely. There is no `cancel_transfer` or admin-rescue function anywhere in the contract.

The code comment on `normalize_amount` acknowledges dust loss but only for the case where `fee > 0` absorbs it via `claim_fee`. It does not address the case where `amount_without_fee` itself normalizes to zero:

```
/// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
``` [5](#0-4) 

### Impact Explanation

A user who sets `fee = amount - 1` (the maximum the protocol allows) with a small `amount`, or who transfers any amount smaller than the normalization divisor, will have their tokens permanently locked (for non-deployed tokens) or burned (for deployed tokens) with no recovery path. This constitutes permanent freezing of bridged funds, which is in the critical impact scope.

### Likelihood Explanation

Low-to-medium. The scenario requires `amount_without_fee < 10^(origin_decimals - decimals)`. For the primary NEAR→EVM path (24→18 decimals, divisor = `10^6`), a user setting `fee = amount - 1` with `amount ≤ 10^6` triggers the freeze. A user attempting to offer a high relayer incentive on a small transfer could inadvertently hit this. No attacker profit is required; the loss is borne by the user who submitted the transfer.

### Recommendation

Add a minimum `amount_without_fee` check in `init_transfer` that accounts for the decimal normalization factor of the destination chain. Specifically, after computing `amount_without_fee`, verify that `normalize_amount(amount_without_fee, decimals) > 0` before accepting the transfer. Alternatively, enforce a protocol-wide minimum transfer amount per destination chain that is at least `10^(origin_decimals - decimals)`.

### Proof of Concept

1. Token registered with `origin_decimals = 24`, `decimals = 18` (normalization divisor = `10^6`).
2. User calls `ft_transfer_call` with `amount = 10^6 + 1` (e.g., `1_000_001` yoctoNEAR-equivalent units).
3. User sets `fee = 10^6` in `InitTransferMsg`. The check `fee < amount` passes (`10^6 < 10^6 + 1`).
4. `init_transfer` succeeds: tokens are locked/burned, transfer message stored in `pending_transfers`.
5. Relayer calls `sign_transfer`.
6. `amount_without_fee()` = `10^6 + 1 - 10^6` = `1`.
7. `normalize_amount(1, {origin: 24, decimals: 18})` = `1 / 10^6` = `0`.
8. `require!(amount_to_transfer > 0, ...)` panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
9. No callback is executed; the transfer message is never removed from `pending_transfers`.
10. The user's `10^6 + 1` token units are permanently locked or burned with no recovery mechanism.

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

**File:** near/omni-bridge/src/lib.rs (L655-667)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }

            env::log_str(
                &OmniBridgeEvent::SignTransferEvent {
                    signature,
                    message_payload,
                }
                .to_log_string(),
            );
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
