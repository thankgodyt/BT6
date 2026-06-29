Audit Report

## Title
`init_transfer` Accepts Tokens Without Validating `normalize_amount(amount - fee) > 0`, Permanently Freezing Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

## Summary

`init_transfer` locks user tokens into the bridge after only checking `fee < amount`, without verifying that the net amount survives decimal normalization to a non-zero value. `sign_transfer` enforces this check but panics before reaching the MPC call, so `sign_transfer_callback` — the only path that calls `remove_transfer_message` — is never invoked. The locked tokens have no recovery path and are permanently frozen.

## Finding Description

The two-step outbound flow is: `init_transfer` (locks tokens, stores `TransferMessage`) → `sign_transfer` (requests MPC signature).

**`init_transfer`** only validates: [1](#0-0) 

**`sign_transfer`** enforces the normalization check: [2](#0-1) 

**`normalize_amount`** uses floor division: [3](#0-2) 

For a token with `origin_decimals = 24`, `decimals = 6` (diff = 18), any `amount - fee < 10^18` normalizes to `0`. `sign_transfer` panics at the `require!(amount_to_transfer > 0)` guard before the MPC `sign` call is ever made. Because the MPC call never executes, `sign_transfer_callback` is never reached.

**`sign_transfer_callback`** is the only place `remove_transfer_message` is called for the outbound path: [4](#0-3) 

It only fires on a successful MPC result. Since `sign_transfer` panics before calling MPC, the callback never runs, and the `TransferMessage` remains in `pending_transfers` indefinitely with the tokens locked.

The `normalize_amount` doc comment acknowledges dust locking (`"When fee = 0, dust stays locked/burned"`): [5](#0-4) 

However, this comment refers to sub-unit remainders after normalization, not to the case where the *entire* `amount - fee` normalizes to zero — a qualitatively different and unrecoverable scenario.

## Impact Explanation

Permanent freezing of bridged funds. User tokens are locked in the NEAR `omni-bridge` contract with no admin escape hatch, no `cancel_transfer`, and no refund path. This matches the critical impact class: *permanent freezing of bridged funds*.

## Likelihood Explanation

Any token pair where `origin_decimals > decimals` creates a minimum transferable unit of `10^(origin_decimals - decimals)`. For a 24→6 decimal pair this is `10^18`. A user transferring any amount below this threshold — a realistic mistake given no UI guard and no on-chain rejection at `init_transfer` — permanently loses their funds. Additionally, `update_transfer_fee` allows the sender to raise the token fee post-initiation: [6](#0-5) 

Raising the fee can push a previously valid `amount - fee` below the normalization threshold, triggering the same freeze.

## Recommendation

Add the normalization check inside `init_transfer` (after building `transfer_message`, before storing it) by looking up `token_decimals` for the destination chain and calling `Self::normalize_amount(transfer_message.amount_without_fee()..., decimals)`, then `require!(normalized > 0, BridgeError::InvalidAmountToTransfer)`. Apply the same guard inside `update_transfer_fee` when the token fee is raised, to prevent a valid transfer from being made un-signable after the fact.

## Proof of Concept

1. Deploy a NEAR token with 24 decimals; bind it to an EVM address with `decimals = 6`, `origin_decimals = 24` via `bind_token`.
2. Call `ft_transfer_call` with `amount = 999_999_999_999_999_999` (< 10^18) and `msg` encoding `InitTransferMsg { fee: U128(0), native_token_fee: U128(0), recipient: <EVM address> }`.
3. Observe `init_transfer` succeeds; tokens are deducted from the user and locked in the bridge (only `fee < amount` is checked).
4. Call `sign_transfer` with the resulting `transfer_id`.
5. Observe the call panics with `ERR_INVALID_AMOUNT_TO_TRANSFER` at the `require!(amount_to_transfer > 0)` guard — before the MPC `sign` call is made.
6. Confirm `sign_transfer_callback` is never invoked, `remove_transfer_message` is never called, and no other public function exists to recover the locked tokens.

### Citations

**File:** near/omni-bridge/src/lib.rs (L399-402)
```rust
                require!(
                    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
                    BridgeError::InvalidFee.as_ref()
                );
```

**File:** near/omni-bridge/src/lib.rs (L471-485)
```rust
        let decimals = self
            .token_decimals
            .get(&token_address)
            .near_expect(BridgeError::TokenDecimalsNotFound);
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
