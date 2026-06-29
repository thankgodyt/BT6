Audit Report

## Title
Unchecked `u128` Multiplication Overflow in `denormalize_amount` Permanently Freezes Bridged Funds — (File: near/omni-bridge/src/lib.rs)

## Summary

`denormalize_amount` performs a bare `u128` multiplication with no overflow guard. The workspace release profile enables `overflow-checks = true`, so any overflow panics at runtime. When triggered inside `fin_transfer_callback` after the EVM side has already locked or burned tokens, the callback aborts, the NEAR-side transfer is never finalized, and the user's funds are permanently frozen with no recovery path.

## Finding Description

`denormalize_amount` is defined as a bare multiplication: [1](#0-0) 

The workspace release profile unconditionally enables overflow checks: [2](#0-1) 

This means any `amount * 10^diff_decimals` exceeding `u128::MAX` causes an immediate panic/abort rather than silent wrapping.

`denormalize_amount` is called unconditionally at three call sites:

1. Inside `fin_transfer_callback` to reconstruct the NEAR-side amount from the EVM proof: [3](#0-2) 

2. Inside `fast_fin_transfer`: [4](#0-3) 

3. Inside `claim_fee_callback`: [5](#0-4) 

The `Decimals` struct stores both `decimals` (EVM-side) and `origin_decimals` (NEAR-side) as `u8` values: [6](#0-5) 

For a token with `origin_decimals = 24` and `decimals = 18` (`diff_decimals = 6`), the overflow threshold is `u128::MAX / 10^6 ≈ 3.4 × 10^32` — well within the `uint128` range accepted by the EVM `initTransfer`. No existing guard in `fin_transfer_callback` or `denormalize_amount` prevents this path.

## Impact Explanation

This directly matches the Critical allowed impact: **permanent freezing of bridged funds**. Once the EVM side locks or burns tokens and the relayer submits the proof, every subsequent call to `fin_transfer` for that transfer will hit the same panic. The destination nonce is never marked used, but the EVM-side lock/burn is irreversible. The user's funds are permanently unrecoverable with no protocol-level escape hatch.

## Likelihood Explanation

Any unprivileged bridge user can trigger this by calling `initTransfer` on the EVM contract with a `uint128` amount above the overflow threshold for the token's decimal configuration. No special role, key, or collusion is required. The EVM contract imposes no upper bound on `amount` beyond the `fee < amount` check. Tokens with large decimal gaps (e.g., NEAR native token: `origin_decimals = 24`, `decimals = 18`, `diff_decimals = 6`) are directly affected with a threshold of ~`3.4 × 10^32`, which is a valid `uint128` value. Tokens with larger gaps (e.g., `diff_decimals = 18`) lower the threshold to ~`3.4 × 10^20`, making the attack trivially reachable with moderate token amounts.

## Recommendation

Replace the bare multiplication with a checked variant and propagate the error:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> Option<u128> {
    let diff_decimals: u32 = decimals.origin_decimals.checked_sub(decimals.decimals)?.into();
    amount.checked_mul(10_u128.checked_pow(diff_decimals)?)
}
```

All three call sites (`fin_transfer_callback`, `fast_fin_transfer`, `claim_fee_callback`) should handle `None` by panicking with a descriptive `BridgeError` rather than allowing an arithmetic abort to propagate. Additionally, consider enforcing an upper-bound check on the EVM `initTransfer` amount relative to the token's decimal configuration so that overflowing amounts are rejected at the source before tokens are locked or burned.

## Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (`diff_decimals = 6`).
2. Attacker calls `initTransfer` on EVM with `amount = u128::MAX / 10^6 + 1` (a valid `uint128`). EVM locks/burns the tokens.
3. Relayer submits the EVM proof to NEAR `fin_transfer` → `fin_transfer_callback`.
4. Inside the callback: `denormalize_amount(amount, decimals)` computes `(u128::MAX / 10^6 + 1) * 10^6`, which exceeds `u128::MAX`. With `overflow-checks = true` in the release profile, the NEAR runtime panics.
5. The callback aborts; no state is written; the destination nonce is never marked used.
6. Every subsequent retry by any relayer produces the same panic.
7. The attacker's (or victim's) tokens are permanently frozen on EVM with no NEAR-side release possible.

A fuzz test targeting `denormalize_amount` with `origin_decimals > decimals` and `amount > u128::MAX / 10^(origin_decimals - decimals)` will reproduce the panic deterministically.

### Citations

**File:** near/omni-bridge/src/lib.rs (L722-726)
```rust
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
```

**File:** near/omni-bridge/src/lib.rs (L770-772)
```rust
        let denormalized_amount =
            Self::denormalize_amount(fast_fin_transfer_msg.amount.0, decimals);
        let denormalized_fee = Self::denormalize_fee(&fast_fin_transfer_msg.fee, decimals);
```

**File:** near/omni-bridge/src/lib.rs (L1122-1127)
```rust
        let denormalized_amount = Self::denormalize_amount(
            fin_transfer.amount.0,
            self.token_decimals
                .get(&token_address)
                .near_expect(BridgeError::TokenDecimalsNotFound),
        );
```

**File:** near/omni-bridge/src/lib.rs (L2776-2779)
```rust
    fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount * (10_u128.pow(diff_decimals))
    }
```

**File:** near/Cargo.toml (L24-31)
```text
[profile.release]
codegen-units = 1
# Tell `rustc` to optimize for small code size.
opt-level = "z"
lto = true
debug = false
panic = "abort"
overflow-checks = true
```

**File:** near/omni-bridge/src/storage.rs (L131-136)
```rust
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decimals {
    pub decimals: u8,
    pub origin_decimals: u8,
}
```
