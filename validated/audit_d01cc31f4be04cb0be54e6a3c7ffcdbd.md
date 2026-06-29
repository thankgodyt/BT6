Audit Report

## Title
Transfer Permanently Frozen When `normalize_amount(amount - fee) == 0` Due to Missing Pre-validation — (`near/omni-bridge/src/lib.rs`)

## Summary

`init_transfer` accepts outbound transfers without verifying that `normalize_amount(amount - fee) > 0`. When `sign_transfer` is later called, it computes this normalization and panics if the result is zero. Because no cancel or refund path exists for the sender, the locked tokens are permanently frozen in the bridge contract.

## Finding Description

**Root cause — `init_transfer` only checks `fee < amount`:**

At `near/omni-bridge/src/lib.rs` lines 554–557, the only amount constraint enforced is:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

No normalization check is performed. Tokens are immediately locked when `ft_on_transfer` returns `U128(0)`.

**`normalize_amount` uses floor division** (`near/omni-bridge/src/lib.rs` lines 2784–2787):

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

For a token with `origin_decimals = 18` and `decimals = 6`, `diff_decimals = 12`. Any `amount - fee < 10^12` normalizes to 0.

**`sign_transfer` panics on zero** (`near/omni-bridge/src/lib.rs` lines 475–485):

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

Every call to `sign_transfer` for this transfer reverts. The transfer remains in `pending_transfers` indefinitely.

**No cancel path exists:** A grep for `cancel_transfer` in `near/omni-bridge/src/lib.rs` returns no matches. There is no user-accessible function to remove a stuck transfer or recover locked tokens.

**`amount_without_fee` implementation** (`near/omni-types/src/lib.rs` lines 593–595):

```rust
pub fn amount_without_fee(&self) -> Option<u128> {
    self.amount.0.checked_sub(self.fee.fee.0)
}
```

Note: The inline SECURITY.md comment at line 2781–2782 acknowledges that "dust stays locked/burned" when fee = 0, but this refers only to sub-unit remainders after a successful normalization — it does not address the case where the entire net amount normalizes to 0 and `sign_transfer` panics.

## Impact Explanation

This constitutes **permanent freezing of bridged funds**, which is explicitly listed as a Critical impact in the allowed scope. The user's tokens are locked in the bridge contract with no mechanism for recovery. The contract itself acknowledges the dust-locking behavior in comments, but the case where `normalize_amount` returns 0 causes a qualitatively different outcome: the transfer is permanently deadlocked rather than partially completed.

## Likelihood Explanation

Any unprivileged user can trigger this by calling `ft_transfer_call` with an `InitTransferMsg` whose `amount - fee` is below the normalization threshold. For 18→6 decimal tokens (a common ERC-20 bridging scenario), the threshold is `10^12` base units (e.g., 0.000001 of an 18-decimal token). No special privileges, coordination, or external conditions are required. The attacker can also be the victim — a user making a small legitimate transfer triggers this inadvertently.

## Recommendation

Add a normalization check inside `init_transfer_internal` (or immediately after the `fee < amount` check in `init_transfer`) before accepting the transfer:

```rust
let token_address = self.get_token_address(
    transfer_message.get_destination_chain(),
    self.get_token_id(&transfer_message.token),
).near_expect(BridgeError::FailedToGetTokenAddress);

let decimals = self.token_decimals
    .get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);

let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This mirrors the check already present in `sign_transfer` and ensures the transfer is rejected at initiation time — causing `ft_on_transfer` to return the full `amount` as a refund — rather than silently accepted and permanently frozen.

## Proof of Concept

1. Register a token with `origin_decimals = 18`, `decimals = 6` (diff = 12).
2. Call `ft_transfer_call` with `amount = 999_999_999_999` (i.e., `10^12 - 1`) and `fee = 0`.
3. `init_transfer` accepts: `0 < 999_999_999_999` passes. Tokens are locked.
4. Relayer calls `sign_transfer` for this transfer ID.
5. `normalize_amount(999_999_999_999, {origin: 18, dest: 6}) = 999_999_999_999 / 10^12 = 0`.
6. `require!(0 > 0, BridgeError::InvalidAmountToTransfer)` panics → transaction reverts.
7. Transfer remains in `pending_transfers`. Tokens remain locked. No cancel path exists.
8. Funds are permanently frozen.