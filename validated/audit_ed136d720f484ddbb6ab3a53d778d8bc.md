Audit Report

## Title
Tokens Permanently Locked When Transfer Amount Normalizes to Zero — (`near/omni-bridge/src/lib.rs`)

## Summary
`init_transfer_internal` locks or burns a user's tokens before any check that the post-normalization transfer amount is greater than zero. The only zero-amount guard lives in `sign_transfer`, which is called later by a relayer. Because `sign_transfer` panics before reaching the MPC signer, `sign_transfer_callback` is never invoked, the transfer record is never removed, and no public cancellation path exists. Any transfer whose normalized amount is zero results in permanent, irrecoverable loss of the user's tokens.

## Finding Description

**Root cause — unconditional lock/burn in `init_transfer_internal`:**

`init_transfer_internal` (lines 1829–1865) locks or burns tokens immediately after storage accounting succeeds, with no check on the normalized transfer amount:

```rust
// near/omni-bridge/src/lib.rs ~line 1850
if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
    self.lock_tokens_if_needed(
        transfer_message.get_destination_chain(),
        &token_id,
        transfer_message.amount.0,
    );
}
```

The function then returns `U128(0)`, signalling to the NEP-141 token contract that all tokens were consumed (no refund).

**The zero-amount guard fires too late — in `sign_transfer`:**

```rust
// near/omni-bridge/src/lib.rs ~line 475
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

`normalize_amount` performs floor division:

```rust
// near/omni-bridge/src/lib.rs ~line 2784
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

For a token with `origin_decimals = 24` and `decimals = 6` (standard NEAR → EVM pairing), the divisor is `10^18`. Any amount below `10^18` yoctoNEAR normalizes to zero.

**No recovery path:**

`remove_transfer_message` is called in `sign_transfer_callback` only when the MPC signing succeeds and `fee.is_zero()`. Because `sign_transfer` panics at the `require!(amount_to_transfer > 0, ...)` check before the MPC call is ever dispatched, `sign_transfer_callback` is never reached. The transfer record remains in `pending_transfers` indefinitely. There is no public `cancel_transfer` or user-accessible withdrawal function anywhere in the contract.

## Impact Explanation
This is a concrete instance of **permanent freezing of bridged funds on NEAR**. A user's tokens are locked inside the bridge contract with no on-chain path to recover them. The transfer record cannot be finalized (no valid MPC signature can ever be produced for it), cannot be cancelled, and cannot be claimed. This matches the allowed critical impact: *permanent freezing of bridged funds*.

## Likelihood Explanation
The trigger requires no special role or privilege. Any user calling the standard, publicly documented `ft_transfer_call` flow with an amount below the normalization threshold (e.g., any amount < 1 NEAR for a 24→6 decimal token) hits this path. The 24-decimal NEAR / 6-decimal EVM pairing is the most common configuration. A user testing with a small amount, sending "dust," or miscalculating units can trigger this trivially and repeatedly.

## Recommendation
Add a normalization check inside `init_transfer_internal` (or in the callers that build `transfer_message`) before tokens are locked or burned. Reject the transfer if the normalized amount would be zero:

```rust
// Before burn_tokens_if_needed / lock_tokens_if_needed
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

Alternatively, add a `cancel_transfer` function that allows the original sender to reclaim tokens from a transfer that has never been signed.

## Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 6`.
2. Call `ft_transfer_call` with `amount = 999_999_999_999_999_999` (below `10^18`), `fee = 0`, valid recipient.
3. `init_transfer_internal` succeeds: tokens are locked/burned, transfer stored in `pending_transfers`, `ft_on_transfer` returns `U128(0)` — tokens consumed, no refund.
4. Relayer calls `sign_transfer` for the new `TransferId`.
5. `normalize_amount(999_999_999_999_999_999, Decimals { decimals: 6, origin_decimals: 24 })` = `999_999_999_999_999_999 / 10^18` = `0`.
6. `require!(0 > 0, ...)` panics — MPC call never dispatched, `sign_transfer_callback` never reached, transfer record untouched.
7. No further call can complete or cancel this transfer; the user's tokens are permanently locked. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
