Audit Report

## Title
Pre-Transfer Normalization Check Missing Causes Permanent Fund Loss for Sub-Unit Amounts — (File: `near/omni-bridge/src/lib.rs`)

## Summary
`init_transfer_internal` burns or locks user tokens before any normalization validation occurs. When a user initiates a NEAR→EVM transfer with an amount smaller than the normalization factor (`10^(origin_decimals − decimals)`), the tokens are irreversibly consumed on NEAR, but `sign_transfer` will always revert on the post-burn guard `require!(amount_to_transfer > 0, …)`, leaving the transfer permanently stuck with no user-accessible recovery path.

## Finding Description
`normalize_amount` (lines 2784–2787) performs integer floor-division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

`sign_transfer` enforces a post-normalization guard (lines 475–485) that panics when the normalized amount is zero. However, by the time `sign_transfer` is called, `init_transfer_internal` (lines 1850–1857) has already burned deployed tokens or locked native tokens:

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(
    transfer_message.get_destination_chain(),
    &token_id,
    transfer_message.amount.0,
);
```

The only pre-acceptance check in `init_transfer` (lines 554–557) is:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

There is no check that `normalize_amount(amount − fee, decimals) > 0` before tokens are consumed. The developer comment at lines 2781–2783 explicitly acknowledges the floor-division behavior ("When fee = 0, dust stays locked/burned. See SECURITY.md for details"), but the referenced SECURITY.md contains only a generic exclusion list and does not document this as an accepted design decision or out-of-scope behavior. No `cancel_transfer` or `set_locked_tokens` function exists in the contract, confirming there is no user-accessible or even admin-accessible recovery path for burned tokens.

## Impact Explanation
This matches the Critical allowed impact: **permanent loss of bridged funds**. For deployed tokens (originated from another chain), the tokens are burned on NEAR and are unrecoverable by any mechanism. For native NEAR tokens, they are locked in the bridge with no cancel or refund function available. The transfer record is stored but can never be successfully signed, leaving funds permanently frozen.

## Likelihood Explanation
The condition is reachable for any registered token pair where `origin_decimals > decimals`. An unprivileged user triggers it via a standard `ft_transfer_call` with a sub-unit amount. This can occur accidentally through UI rounding, dust from prior operations, or deliberate induction by a malicious front-end. No special privileges or external conditions are required.

## Recommendation
Add a normalization guard inside `init_transfer` (or at the top of `init_transfer_internal`) **before** burning or locking tokens:

```rust
let decimals = self.token_decimals.get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);
require!(
    Self::normalize_amount(
        transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
        decimals,
    ) > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

This mirrors the existing guard in `sign_transfer` but places it at the point where the user's funds are still safe and the transaction can revert cleanly.

## Proof of Concept
1. Register a token with `origin_decimals = 24`, `decimals = 6` (normalization factor = 10¹⁸).
2. User calls `ft_transfer_call` with `amount = 1` (1 yoctoNEAR), `fee = 0`.
3. `init_transfer` passes the only check: `0 < 1` (line 554–557).
4. `init_transfer_internal` burns 1 yoctoNEAR and stores the transfer message (lines 1850–1857).
5. A trusted relayer calls `sign_transfer`.
6. `normalize_amount(1, Decimals{decimals:6, origin_decimals:24})` = `1 / 10¹⁸` = **0** (lines 2784–2787).
7. `require!(amount_to_transfer > 0, …)` panics; the transaction reverts (lines 482–485).
8. The user's 1 yoctoNEAR is permanently burned. No cancel or refund mechanism exists in the contract.