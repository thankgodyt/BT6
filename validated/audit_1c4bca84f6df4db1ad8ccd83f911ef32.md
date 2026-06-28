### Title
`normalize_amount` Integer Division Truncation to Zero Permanently Locks User Funds in `init_transfer` — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

When a user initiates a NEAR→foreign transfer of a small amount of a token with a large decimal difference between origin and destination chains, `normalize_amount` truncates the transfer amount to zero via integer floor division. The bridge locks the user's tokens in `init_transfer` without first verifying that the normalized amount is non-zero. When a relayer subsequently calls `sign_transfer`, it always fails with `ERR_INVALID_AMOUNT_TO_TRANSFER`. No cancel or refund mechanism exists, so the user's tokens are permanently frozen in the bridge.

---

### Finding Description

`normalize_amount` performs integer floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

When `amount < 10^diff_decimals`, the result is `0`.

The `init_transfer` function (called from `ft_on_transfer` during `ft_transfer_call`) only validates that `fee.fee < amount`:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

It does **not** check whether `normalize_amount(amount_without_fee, decimals) > 0`. The `TransferMessage` is stored and the tokens are locked (bridge returns `0` from `ft_on_transfer`, keeping all tokens) before any normalization check occurs.

Later, `sign_transfer` computes the normalized amount and enforces the non-zero check:

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

Because the normalized amount is deterministically `0` for the given `(amount, decimals)` pair, every call to `sign_transfer` for this transfer will fail. The `TransferMessage` is only removed by `remove_transfer_message` inside `claim_fee_callback` (requires a destination-chain finalization proof) or inside `sign_transfer_callback` (only when `fee.is_zero()` and signing succeeded). Neither path is reachable when `sign_transfer` always reverts. The user cannot increase `amount_without_fee` either, because `update_transfer_fee` only allows the fee to be raised, not lowered.

---

### Impact Explanation

The user's tokens are permanently frozen inside the bridge contract. The `TransferMessage` occupies storage indefinitely but can never be finalized or cancelled. This satisfies the critical impact criterion: **permanent freezing of bridged funds**.

---

### Likelihood Explanation

The condition is reachable for any token pair where `origin_decimals > decimals` and the user sends an amount below the normalization threshold. A concrete, realistic example:

- NEAR-native token: `origin_decimals = 24`, destination EVM token: `decimals = 6` → `diff = 18`, threshold = `10^18` base units = 1 NEAR.
- Any user bridging fewer than 1 NEAR-equivalent of such a token triggers the bug.

This decimal configuration is common (NEAR uses 24 decimals; many EVM tokens use 6 or 8). The user-facing `init_transfer` API accepts the transaction without error,