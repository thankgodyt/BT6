Audit Report

## Title
Decimal Normalization in `sign_transfer` Can Permanently Lock User Funds for Sub-Threshold Transfers — (File: `near/omni-bridge/src/lib.rs`)

## Summary
`init_transfer` locks or burns user tokens without verifying that the net transfer amount survives the later `normalize_amount` floor-division step. When a user initiates a transfer whose `amount_without_fee()` is less than `10^(origin_decimals − decimals)`, `sign_transfer` computes a normalized amount of zero and panics on the `require!(amount_to_transfer > 0)` guard. Because the panic occurs before the MPC async call, `sign_transfer_callback` is never reached, and no on-chain path exists to remove the stuck `TransferMessage` or refund the locked tokens.

## Finding Description

**Root cause — missing pre-validation in `init_transfer`.**

`init_transfer` (via `ft_on_transfer`) builds the `TransferMessage` and checks only that `fee < amount`: [1](#0-0) 

It then calls `init_transfer_internal`, which immediately stores the message, burns (for deployed tokens) or locks the full amount, and emits the event — all without checking whether `normalize_amount(amount_without_fee())` is positive: [2](#0-1) 

**`normalize_amount` uses floor division.**

For a 24-decimal NEAR token bridged to a 6-decimal EVM representation, `diff_decimals = 18`. Any net amount below `10^18` base units divides to zero: [3](#0-2) 

**`sign_transfer` panics after tokens are already locked.**

`sign_transfer` calls `normalize_amount` on `amount_without_fee()` and then asserts the result is positive. The panic occurs synchronously, before the `ext_signer` MPC call is dispatched: [4](#0-3) 

**No cancellation path exists.**

`remove_transfer_message` is only reachable inside `sign_transfer_callback` (when `fee.is_zero()` and the MPC call succeeded) or `claim_fee_callback`. Neither is reachable when `sign_transfer` panics before the async call: [5](#0-4) 

`remove_transfer_message_without_refund` is only called inside `init_transfer_internal` on storage-balance failure, before tokens are locked. A search for `rescue`, `cancel_transfer`, `refund_transfer`, and `emergency` in `lib.rs` returns no matches — confirming there is no DAO or admin escape hatch.

**The CLAUDE.md false-positive note does not cover this case.**

The note at L192–196 addresses arithmetic underflow when `origin_decimals < decimals` (the subtraction itself panics). The present issue arises when `origin_decimals >= decimals` but the amount is so small that the floor division silently produces zero — a distinct code path: [6](#0-5) 

## Impact Explanation
User tokens are permanently frozen in `pending_transfers` with no on-chain recovery mechanism. For deployed (bridged) tokens, `burn_tokens_if_needed` is called at lock time, making the loss irreversible even at the token-supply level. This constitutes **permanent freezing of bridged funds**, matching the Critical allowed impact scope.

## Likelihood Explanation
The trigger condition is `amount_without_fee() < 10^diff_decimals`. For a 24-decimal NEAR token bridged to a 6-decimal EVM representation, the threshold is `10^18` base units (= 0.000001 of the token). The bridge imposes no minimum-amount guard at `init_transfer` time. Any user who sends a transfer below this threshold — whether by accident, UI rounding error, or intentional dust transfer — will have their funds permanently locked. No privileged access is required; the path is reachable through the standard `ft_transfer_call` public callback.

## Recommendation
Add a normalizability check inside `init_transfer` (before `init_transfer_internal` is called and tokens are locked) that mirrors the check already present in `sign_transfer`:

```rust
// After building transfer_message and before init_transfer_internal:
if let Some(token_address) = self.get_token_address(
    transfer_message.get_destination_chain(),
    self.get_token_id(&transfer_message.token),
) {
    if let Some(decimals) = self.token_decimals.get(&token_address) {
        let net = transfer_message
            .amount_without_fee()
            .expect("fee < amount already checked");
        require!(
            Self::normalize_amount(net, decimals) > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );
    }
}
```

Alternatively, add a DAO-callable rescue function that can remove a stuck `pending_transfer` and refund the storage owner.

## Proof of Concept

1. A NEAR-native token has `origin_decimals = 24` on NEAR and `decimals = 6` on the EVM destination (`diff_decimals = 18`).
2. User calls `ft_transfer_call` with `amount = 5 × 10^17` (0.0000005 of the token) and `fee = 0`.
3. `init_transfer` passes the `fee < amount` guard (0 < 5×10^17), stores the `TransferMessage`, and locks `5 × 10^17` units via `lock_tokens_if_needed` / `burn_tokens_if_needed`.
4. Trusted relayer calls `sign_transfer` for this transfer.
5. `normalize_amount(5 × 10^17, Decimals { decimals: 6, origin_decimals: 24 })` = `5 × 10^17 / 10^18` = **0**.
6. `require!(amount_to_transfer > 0, ...)` **panics**; the transaction reverts. The MPC call is never dispatched.
7. `sign_transfer_callback` is never reached; `remove_transfer_message` is never called.
8. The `TransferMessage` remains in `pending_transfers`; the user's `5 × 10^17` units are permanently locked with no on-chain recovery path.

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

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```

**File:** near/CLAUDE.md (L192-196)
```markdown
**2. Decimal Arithmetic Underflow (NOT a vulnerability)**
- Design expects `origin_decimals >= decimals` (normalization to lower precision)
- Workspace has `overflow-checks = true` in Cargo.toml
- Misconfiguration causes panic (correct fail-safe), not silent corruption

```
