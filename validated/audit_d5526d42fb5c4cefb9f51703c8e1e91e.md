Audit Report

## Title
Decimal Normalization Floor Division Permanently Freezes Bridged Funds When `normalize_amount(amount_without_fee)` Rounds to Zero - (File: `near/omni-bridge/src/lib.rs`)

## Summary

`init_transfer` locks user tokens after only verifying `fee < amount`, without checking that the post-normalization transferable amount is non-zero. When `normalize_amount(amount_without_fee())` rounds to zero via floor division, `sign_transfer` permanently panics with `InvalidAmountToTransfer`. No cancel or refund path is reachable from this state, making the locked tokens irrecoverable.

## Finding Description

`normalize_amount` performs floor division to convert NEAR-side token amounts to destination-chain representation:

```rust
// near/omni-bridge/src/lib.rs L2784-2787
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

The code comment at L2781-2783 explicitly acknowledges: *"When fee = 0, dust stays locked/burned."*

`init_transfer_internal` stores the transfer and locks tokens after only checking:

```rust
// near/omni-bridge/src/lib.rs L554-557
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

No validation that `normalize_amount(amount_without_fee()) > 0` is performed at this stage. Later, `sign_transfer` computes and checks the normalized amount:

```rust
// near/omni-bridge/src/lib.rs L475-485
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

`amount_without_fee()` is a simple subtraction (`near/omni-types/src/lib.rs` L593-595). If the result is positive but less than `10^(origin_decimals - decimals)`, `normalize_amount` returns 0 and `sign_transfer` always panics.

**No recovery path exists:**
- `remove_transfer_message` is called in `sign_transfer_callback` only when `fee.is_zero()` and signing succeeds (L657) — unreachable since signing panics before the callback.
- `claim_fee_callback` requires a finalization proof from the destination chain — impossible since the transfer was never signed.
- `fin_transfer_send_tokens_callback` requires a successful token send — also unreachable.
- `update_transfer_fee` (L399-401) only allows fee *increases* (`fee.fee >= current_fee.fee`), which further reduces `amount_without_fee()` and cannot rescue the transfer.

## Impact Explanation

Any user tokens locked by `init_transfer` where `normalize_amount(amount_without_fee()) = 0` are permanently frozen in the bridge contract with no recovery mechanism. This directly matches the Critical impact category: **permanent freezing of bridged funds**. The code comment itself acknowledges the dust-locking behavior, confirming the design does not handle this edge case.

## Likelihood Explanation

The condition is reachable by any unprivileged user calling `ft_transfer_call` with no special role or permission. The standard NEAR (24 decimals) to EVM (18 decimals) configuration creates a divisor of 1,000,000, meaning any transfer where `amount_without_fee < 1,000,000` triggers the freeze. Users may hit this accidentally with small amounts or by setting a fee that leaves a sub-unit remainder (e.g., amount = 1,500,000, fee = 1,000,000 → `amount_without_fee` = 500,000 → normalized = 0). This is a realistic production scenario.

## Recommendation

In `init_transfer_internal`, after constructing the `TransferMessage`, look up the token's registered `Decimals` and compute `normalize_amount(amount_without_fee())`. If the result is zero, do not store the transfer message or lock tokens — instead return the full `amount` from `ft_on_transfer` to trigger the NEP-141 automatic refund to the sender.

Alternatively, implement a `cancel_transfer` function callable by the original sender that removes the pending transfer message and refunds the locked tokens via `ft_transfer`. This would also mitigate other stuck-transfer scenarios.

## Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (divisor = 1,000,000).
2. Call `ft_transfer_call` with `amount = 500_000`, `fee = 0`, and a valid Ethereum recipient.
3. `init_transfer` passes the `fee < amount` check (0 < 500,000) and locks 500,000 units in the bridge contract.
4. Relayer calls `sign_transfer` → `normalize_amount(500_000, {24, 18})` = 500,000 / 1,000,000 = 0 → panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
5. No cancel path exists. Tokens remain permanently locked.

**Test plan:** Write a NEAR sandbox integration test that (a) registers a token with a 6-decimal gap, (b) calls `ft_transfer_call` with `amount = 500_000`, (c) asserts the transfer message is stored, (d) calls `sign_transfer` and asserts it panics with `InvalidAmountToTransfer`, and (e) asserts no refund or cancel function can remove the stored transfer message.