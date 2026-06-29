Audit Report

## Title
Missing Normalization Pre-Check in `init_transfer` Permanently Locks Sub-Unit Transfers — (File: `near/omni-bridge/src/lib.rs`)

## Summary

`init_transfer` stores outbound transfers after only verifying `fee.fee < amount`, without checking that `normalize_amount(amount - fee) > 0`. When a user sends an amount smaller than the decimal-normalization divisor, the transfer is accepted and tokens are locked, but every subsequent call to `sign_transfer` panics before reaching the MPC signer. No cancellation path exists, making the lock permanent.

## Finding Description

**Root cause — missing pre-check in `init_transfer`:** [1](#0-0) 

The only validation is `fee.fee < amount`. There is no check that `normalize_amount(amount - fee) > 0`.

**Panic in `sign_transfer`:** [2](#0-1) 

`normalize_amount` uses floor division: [3](#0-2) 

For a token with `origin_decimals=24, decimals=18` (divisor = 10^6), any `amount - fee < 1,000,000` produces `normalize_amount(...) = 0`, triggering the `require!(amount_to_transfer > 0, ...)` panic. The MPC signer is never called.

**`sign_transfer_callback` is never reached:** [4](#0-3) 

Transfer removal only happens inside this callback (when `fee.is_zero()`). Because `sign_transfer` panics before dispatching the MPC promise, the callback is never invoked and the transfer stays in `pending_transfers` indefinitely.

**`update_transfer_fee` cannot rescue the transfer:** [5](#0-4) 

The fee can only be raised to `amount - 1` (strict less-than), so `amount_without_fee` can be reduced to `1` but never to `0`. `normalize_amount(1) = 0` still panics.

No `cancel_transfer` or admin-rescue function exists in the contract.

## Impact Explanation

Any user who initiates an outbound transfer where `(amount - fee) < 10^(origin_decimals - decimals)` permanently loses their tokens. The tokens are locked in the bridge contract with no recovery path. This constitutes **permanent freezing of bridged funds**, matching the Critical impact scope.

The code comment at L2781–2783 acknowledges that "dust stays locked/burned" for the fee=0 case, but this refers to small remainders after normalization, not the scenario where the *entire* `amount - fee` normalizes to zero — a materially more severe outcome.

## Likelihood Explanation

Tokens with a 6-decimal gap (e.g., NEAR-native 24-decimal tokens bridged to 18-decimal EVM chains) are common. Any user sending fewer than 1,000,000 base units triggers the bug. No special privileges are required — any unprivileged user can trigger this via `ft_transfer_call`. This is a realistic user error for dust or low-value transfers.

## Recommendation

Add a normalization check inside `init_transfer` (or `init_transfer_internal`) before storing the transfer, after looking up token decimals:

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

Alternatively, add a `cancel_transfer` function allowing the original sender to reclaim tokens from a transfer that has never been signed.

## Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (divisor = 1,000,000).
2. User calls `ft_transfer_call` with `amount = 500_000`, `fee = 0`.
3. `init_transfer` passes: `0 < 500_000` ✓. Transfer stored; 500,000 tokens locked.
4. Relayer calls `sign_transfer(transfer_id, None, None)`.
5. `normalize_amount(500_000, {origin: 24, decimals: 18}) = 500_000 / 1_000_000 = 0`.
6. `require!(0 > 0, BridgeError::InvalidAmountToTransfer)` panics.
7. No MPC call is dispatched. `sign_transfer_callback` is never reached. Transfer remains in `pending_transfers`.
8. `claim_fee` cannot be called (no destination-chain finalization proof exists).
9. `update_transfer_fee` cannot help (fee can only reach `amount - 1 = 499_999`; `normalize_amount(1) = 0` still panics).
10. User's 500,000 tokens are permanently locked with no recovery path.

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

**File:** near/omni-bridge/src/lib.rs (L649-668)
```rust
    pub fn sign_transfer_callback(
        &mut self,
        #[callback_result] call_result: Result<SignatureResponse, PromiseError>,
        #[serializer(borsh)] message_payload: TransferMessagePayload,
        #[serializer(borsh)] fee: &Fee,
    ) {
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
    }
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
