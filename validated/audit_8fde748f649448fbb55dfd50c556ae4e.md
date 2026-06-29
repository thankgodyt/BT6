Audit Report

## Title
Missing Minimum Amount Validation After Decimal Normalization in `init_transfer` Leads to Permanent Fund Freezing - (File: near/omni-bridge/src/lib.rs)

## Summary

The `init_transfer` function locks or burns user tokens and stores a pending transfer without verifying that the transferred amount produces a non-zero value after decimal normalization. The zero-amount guard exists only in `sign_transfer`, which is called after tokens are already irrecoverably committed. Any user who initiates a NEAR → Foreign transfer with an amount below the normalization threshold will have their tokens permanently frozen with no recovery path.

## Finding Description

`normalize_amount` performs floor division by `10^(origin_decimals - decimals)`: [1](#0-0) 

The zero-amount guard is placed exclusively inside `sign_transfer`, after the MPC signing flow begins: [2](#0-1) 

`init_transfer` only validates `fee < amount` before proceeding: [3](#0-2) 

It then calls `init_transfer_internal`, which stores the transfer message and burns or locks the tokens unconditionally: [4](#0-3) 

Once tokens are burned/locked and the transfer is stored in `pending_transfers`, every subsequent `sign_transfer` call will compute `normalize_amount(amount, decimals) = 0` and revert with `ERR_INVALID_AMOUNT_TO_TRANSFER`. The `remove_transfer_message` call in `sign_transfer_callback` only executes on a *successful* signing when fee is zero: [5](#0-4) 

No public cancel or refund function exists for this stuck state. Notably, the `normalize_amount` comment acknowledges that "When fee = 0, dust stays locked/burned" but does not address the case where the entire amount normalizes to zero: [6](#0-5) 

## Impact Explanation

This directly matches the allowed critical impact: **permanent freezing of bridged funds**. For a token configured with `origin_decimals = 24` and `decimals = 18` (a common configuration), any transfer amount below `1_000_000` base units normalizes to zero. The tokens are burned on NEAR, the transfer record is permanently stuck in `pending_transfers`, and no on-chain mechanism exists to recover the funds. The loss is irreversible.

## Likelihood Explanation

The condition is reachable by any unprivileged token holder via `ft_on_transfer`. A decimal gap between origin and NEAR representation is a normal, expected configuration. The `init_transfer` call succeeds and emits an `InitTransferEvent`, giving the user no indication the transfer can never be finalized. The condition is silently triggerable, repeatable, and requires no special privileges or coordination.

## Recommendation

Add the normalization check inside `init_transfer`, before `init_transfer_internal` is called. Retrieve the token's `Decimals` for the destination chain at transfer initiation time and assert:

```rust
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This ensures tokens are never committed for a transfer that can never be signed.

## Proof of Concept

1. Deploy a token with `origin_decimals = 24`, `decimals = 18` (diff = 6) and register it with the bridge.
2. User calls `ft_on_transfer` transferring `amount = 500_000` with `fee = 0`. The check `fee < amount` passes. `init_transfer_internal` is called: tokens are burned, transfer stored with nonce N.
3. Relayer calls `sign_transfer({ Near, N }, ...)`.
4. `normalize_amount(500_000, Decimals { origin_decimals: 24, decimals: 18 })` = `500_000 / 1_000_000` = **0**.
5. `require!(0 > 0, ERR_INVALID_AMOUNT_TO_TRANSFER)` panics. MPC signing never proceeds.
6. The transfer record remains in `pending_transfers` permanently; the 500,000 tokens are burned with no recourse. No cancel path exists to recover them.

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
