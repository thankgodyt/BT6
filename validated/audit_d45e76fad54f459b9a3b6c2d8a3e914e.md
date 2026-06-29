Audit Report

## Title
Inconsistent fee-vs-amount validation between `init_transfer` admission and `sign_transfer` execution causes permanent fund freezing — (File: `near/omni-bridge/src/lib.rs`)

## Summary
The admission check in `init_transfer` only enforces `fee < amount`, but `sign_transfer` additionally applies `normalize_amount` (floor division by `10^(origin_decimals - decimals)`) before requiring the result to be nonzero. When `amount - fee` is smaller than the normalization factor, `sign_transfer` always panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`. Because tokens are already burned or locked at admission time and no on-chain cancellation path exists, the funds are permanently frozen.

## Finding Description

**Admission check in `init_transfer`** only enforces `fee < amount`: [1](#0-0) 

A transfer with `amount = 1_000_000` and `fee = 999_999` passes this gate.

**`sign_transfer` applies `normalize_amount` and requires the result to be nonzero:** [2](#0-1) 

**`normalize_amount` performs floor division:** [3](#0-2) 

For a NEAR-native token with `origin_decimals = 24` bridged to an EVM chain with `decimals = 18`, the divisor is `10^6`. If `amount - fee = 1`, then `normalize_amount(1, {24, 18}) = 0`, and `sign_transfer` panics unconditionally.

**Tokens are burned/locked at admission time**, before `sign_transfer` is ever called: [4](#0-3) 

**No cancellation path exists.** `sign_transfer_callback` only removes the transfer message when `fee.is_zero()` AND signing succeeds: [5](#0-4) 

`claim_fee_callback` requires a proof of finalization on the destination chain, which can never be produced for a transfer that `sign_transfer` always rejects. The transfer remains in `pending_transfers` indefinitely.

**`update_transfer_fee` has the same gap** — it only checks `fee.fee >= current_fee.fee && fee.fee < transfer.message.amount`, allowing a user to raise the fee on an existing transfer until `amount - fee < normalization_factor`, triggering the same permanent freeze: [6](#0-5) 

## Impact Explanation
Any user who initiates a transfer where `amount - fee` is below the decimal normalization threshold permanently loses their bridged tokens. The tokens are locked or burned at `init_transfer` time; `sign_transfer` will always revert with `ERR_INVALID_AMOUNT_TO_TRANSFER`; and no on-chain recovery mechanism exists. This constitutes **permanent freezing of bridged funds** — a concrete critical impact under the allowed scope ("permanent freezing of bridged funds across NEAR, EVM, … flows").

## Likelihood Explanation
The condition is realistic for any token pair where `origin_decimals > decimals` (the standard case for NEAR tokens bridged to EVM chains, e.g., 24 → 18 decimals, normalization factor `10^6`). A user sending a small amount with a high fee, or a user who calls `update_transfer_fee` to raise the fee close to the transfer amount, can trigger this silently. No special privileges are required; the entry path is the public `ft_transfer_call` → `ft_on_transfer` → `init_transfer` flow, or the public `update_transfer_fee` call.

## Recommendation
1. **Tighten the admission gate in `init_transfer`**: after computing `amount_without_fee`, apply `normalize_amount` with the token's registered `Decimals` and reject the transfer if the result is zero, mirroring the check already present in `sign_transfer`.
2. **Apply the same guard in `update_transfer_fee`**: verify that `normalize_amount(amount - new_fee, decimals) > 0` before accepting the updated fee.
3. **Add a cancellation/refund path**: allow the original sender to cancel a pending transfer and recover their tokens if the transfer has not yet been signed, as a defense-in-depth measure.

## Proof of Concept
1. Register a NEAR token with `origin_decimals = 24`, `decimals = 18` (normalization factor = `10^6`).
2. User calls `ft_transfer_call` with `amount = 1_000_000` and `fee = 999_999`.
3. `init_transfer` admission check: `999_999 < 1_000_000` → passes.
4. `init_transfer_internal` burns/locks `1_000_000` tokens from the user.
5. Relayer calls `sign_transfer`.
6. `amount_without_fee = 1_000_000 - 999_999 = 1`.
7. `normalize_amount(1, {origin: 24, dest: 18}) = 1 / 10^6 = 0`.
8. `require!(0 > 0, ...)` → panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
9. Transfer remains in `pending_transfers`; tokens are permanently locked/burned with no recovery path.

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
