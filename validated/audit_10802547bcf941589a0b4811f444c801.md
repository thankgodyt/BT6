Audit Report

## Title
`sign_transfer` permanently freezes funds when decimal-normalized transfer amount rounds to zero — (`near/omni-bridge/src/lib.rs`)

## Summary
When a user initiates a NEAR→Foreign outbound transfer with an amount that, after fee subtraction and decimal normalization, truncates to zero, `sign_transfer` permanently reverts with `ERR_INVALID_AMOUNT_TO_TRANSFER`. Because tokens are already locked or burned at `init_transfer` time and no cancel or refund path exists for pending transfers, the user's funds are permanently frozen on-chain.

## Finding Description

**Root cause — missing pre-normalization guard at `init_transfer` time.**

`init_transfer` (lines 554–557) validates only that `fee.fee < amount`:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

It does **not** verify that `normalize_amount(amount − fee, decimals) > 0`. Immediately after this check, `init_transfer_internal` (lines 1850–1857) locks or burns the full token amount and stores the `TransferMessage` in `pending_transfers`.

**The blocking check — `sign_transfer` (lines 475–485):**

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

**`normalize_amount` (lines 2784–2787) uses floor division:**

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

For any token where `origin_decimals > decimals` (e.g., a NEAR-side token with 24 decimals bridging to a chain where it has 6 decimals, giving a divisor of 10¹⁸), any `amount_without_fee < 10^(origin_decimals − decimals)` normalizes to 0. The `require!` then panics, reverting the transaction.

**No recovery path exists.** The `TransferMessage` remains in `pending_transfers` indefinitely:
- `sign_transfer_callback` only removes the message on MPC signing *success*; it is never reached because `sign_transfer` panics before the MPC call.
- `update_transfer_fee` can only *increase* the fee (line 400: `fee.fee >= current_fee.fee`), which makes `amount_without_fee` smaller, not larger — it cannot fix the condition.
- `claim_fee` requires a proof of finalization on the destination chain, which is impossible for a transfer that was never signed.
- There is no `cancel_transfer` or user-accessible refund function anywhere in the contract.

**Exploit path:**
1. User calls `ft_transfer_call` on a NEAR token with `amount = X` where `X − fee < 10^(origin_decimals − decimals)`.
2. `init_transfer` passes (fee < amount), tokens are locked/burned, `TransferMessage` stored.
3. Relayer calls `sign_transfer`; `normalize_amount` returns 0; `require!` panics.
4. Transaction reverts; `TransferMessage` stays in `pending_transfers`; tokens are permanently frozen.

## Impact Explanation
This is a **permanent freezing of bridged funds** — a Critical impact class explicitly listed in the allowed scope. The user's tokens are locked or burned on NEAR with no on-chain mechanism to recover them. The severity is Critical because the loss is irreversible without a privileged contract upgrade.

## Likelihood Explanation
Any unprivileged user can trigger this by initiating a transfer with a sub-threshold amount via the public `ft_transfer_call` NEP-141 callback. The condition is reachable whenever `origin_decimals > decimals` for a registered token pair. For a 24→6 decimal pair (divisor 10¹⁸), any transfer of fewer than 10¹⁸ base units (a plausible dust or small-value transfer) triggers the freeze. The user need not be malicious; an accidental small transfer suffices. The condition is repeatable for every such transfer.

## Recommendation
Add a normalization guard inside `init_transfer` (before locking tokens) that rejects the transfer if the normalized net amount would be zero:

```rust
let decimals = self.token_decimals.get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

As defense-in-depth, add a user-callable `cancel_transfer` that returns locked tokens to the sender for transfers that have not yet been signed, guarded by a time-lock or sender-only access control.

## Proof of Concept
Minimal unit-test plan (extends the existing `near/omni-bridge/src/tests/lib_test.rs` pattern):

1. Register a token with `Decimals { origin_decimals: 24, decimals: 6 }` (divisor = 10¹⁸).
2. Call `init_transfer` with `amount = 1`, `fee = 0`; assert it succeeds and the `TransferMessage` is stored.
3. Call `sign_transfer` for the same `transfer_id`; assert it panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
4. Assert the `TransferMessage` is still present in `pending_transfers` (i.e., `get_transfer_message` returns it).
5. Assert no `cancel_transfer` or equivalent call can remove it and return the token to the sender.