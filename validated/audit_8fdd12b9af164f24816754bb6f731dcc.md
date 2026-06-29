Based on my code review, all the key claims are verified against the actual source:

- `sign_transfer()` at L447 is `#[trusted_relayer]` gated, normalizes amount at L475-480, and panics at L482-485 if result is 0. [1](#0-0) 
- `normalize_amount` at L2784-2787 uses floor division with no zero-result guard. [2](#0-1) 
- `init_transfer_internal` at L1850-1857 burns/locks tokens unconditionally for NEAR-origin tokens before any normalization check. [3](#0-2) 
- `remove_transfer_message` at L2194 is a private function with no public cancel/refund wrapper. [4](#0-3) 
- `update_transfer_fee` at L399-401 enforces `fee.fee >= current_fee.fee`, only allowing fee increases, and cannot rescue a transfer where even `amount_without_fee = 1` normalizes to 0. [5](#0-4) 
- `init_transfer` wrapper at L554-556 only checks `fee < amount`, not that the normalized `amount_without_fee > 0`. [6](#0-5) 

The vulnerability is real and the PoC is sound. The `#[trusted_relayer]` gate on `sign_transfer` does not mitigate the issue — trusted relayers are expected to process all pending transfers, and they will always fail for this transfer ID, leaving funds permanently frozen.

---

Audit Report

## Title
Missing normalization pre-check in `init_transfer_internal` permanently freezes sub-unit transfer amounts - (File: near/omni-bridge/src/lib.rs)

## Summary
When a user initiates a NEAR → Foreign chain transfer with an `amount_without_fee` smaller than the decimal scaling factor (`10^(origin_decimals - decimals)`), `normalize_amount` returns 0 via floor division. `init_transfer_internal` burns or locks the user's tokens before any normalization check is performed, and `sign_transfer` subsequently panics with `ERR_INVALID_AMOUNT_TO_TRANSFER` on every invocation for that transfer ID. No public cancel or refund path exists, so the funds are permanently frozen.

## Finding Description
`init_transfer_internal` (L1829–1865) unconditionally burns or locks tokens for NEAR-origin transfers and emits `InitTransferEvent` without verifying that the normalized `amount_without_fee` is non-zero:

```rust
// L1850-1857 — tokens burned/locked with no normalization pre-check
if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
    self.lock_tokens_if_needed(...);
}
```

Later, `sign_transfer` (L475–485) normalizes the amount and panics if the result is 0:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

`normalize_amount` (L2784–2787) uses floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

For any `amount_without_fee < 10^(origin_decimals - decimals)`, the result is 0 and `sign_transfer` panics deterministically on every call. `remove_transfer_message` (L2194) is private and only reachable via successful `sign_transfer_callback` or `claim_fee_callback` — neither of which can be reached. `update_transfer_fee` (L399–401) enforces `fee.fee >= current_fee.fee`, so the fee can only be increased, not decreased to rescue the transfer. Even setting `fee = amount - 1` leaves `amount_without_fee = 1`, which still normalizes to 0 for large decimal gaps. The `init_transfer` wrapper only checks `fee < amount` (L554–556), not that the normalized net amount is positive.

## Impact Explanation
Permanent freezing of bridged funds — a Critical impact under the allowed scope. Any user who initiates a NEAR → Foreign transfer where `amount_without_fee < 10^(origin_decimals - decimals)` will have their tokens permanently burned or locked inside the bridge contract with no recovery path. The transfer entry remains in `pending_transfers` indefinitely.

## Likelihood Explanation
Moderate. The decimal gap is largest for tokens with high NEAR-side precision bridging to low-precision destination chains. A token registered with `origin_decimals = 24` and `decimals = 6` (a common USDC-like configuration) has a scaling factor of `10^18`. Any transfer of less than one full destination-chain unit triggers the bug. The entry point (`ft_transfer_call` → `ft_on_transfer` → `init_transfer`) is fully public and requires no special role. Users who set a fee close to their transfer amount, or who are unfamiliar with decimal normalization, can easily fall into this trap.

## Recommendation
Add a normalization pre-check inside `init_transfer_internal` (or in the `init_transfer` wrapper before calling it). If the normalized `amount_without_fee` is zero, return the full token amount as a refund instead of burning/locking, mirroring the existing pattern used when storage balance is insufficient:

```rust
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
if normalized == 0 {
    return transfer_message.amount; // refund to sender
}
```

This check should be placed before `burn_tokens_if_needed` and `lock_tokens_if_needed` in `init_transfer_internal`, or equivalently in the `init_transfer` wrapper after the `fee < amount` guard.

## Proof of Concept
1. Token is registered with `origin_decimals = 24`, `decimals = 6`; scaling factor = `10^18`.
2. User calls `ft_transfer_call` on the token contract, sending `amount = 5 × 10^17` to the bridge with `fee = 0`.
3. `init_transfer_internal` stores the transfer in `pending_transfers`, burns `5 × 10^17` tokens, and emits `InitTransferEvent`. No normalization check occurs.
4. A trusted relayer calls `sign_transfer()`:
   - `amount_without_fee() = 5 × 10^17`
   - `normalize_amount(5 × 10^17, {decimals: 6, origin_decimals: 24}) = 5 × 10^17 / 10^18 = 0`
   - `require!(0 > 0, ERR_INVALID_AMOUNT_TO_TRANSFER)` → panics
5. Every subsequent call to `sign_transfer()` for this transfer ID panics identically.
6. The user's `5 × 10^17` tokens are permanently burned; the transfer entry is permanently stuck in `pending_transfers` with no refund path.

A local integration test can reproduce this by: (a) registering a token with the above decimal configuration, (b) calling `ft_transfer_call` with a sub-unit amount, (c) asserting that `init_transfer_internal` returns `U128(0)` (tokens burned), and (d) asserting that `sign_transfer` panics with `ERR_INVALID_AMOUNT_TO_TRANSFER` on every invocation.

### Citations

**File:** near/omni-bridge/src/lib.rs (L399-401)
```rust
                require!(
                    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
                    BridgeError::InvalidFee.as_ref()
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

**File:** near/omni-bridge/src/lib.rs (L2194-2211)
```rust
    fn remove_transfer_message(&mut self, transfer_id: TransferId) -> TransferMessage {
        let storage_usage = env::storage_usage();
        let transfer = self
            .pending_transfers
            .remove(&transfer_id)
            .map(storage::TransferMessageStorage::into_main)
            .near_expect(BridgeError::TransferNotExist);

        let refund =
            env::storage_byte_cost().saturating_mul((storage_usage - env::storage_usage()).into());

        if let Some(mut storage) = self.accounts_balances.get(&transfer.owner) {
            storage.available = storage.available.saturating_add(refund);
            self.accounts_balances.insert(&transfer.owner, &storage);
        }

        transfer.message
    }
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
