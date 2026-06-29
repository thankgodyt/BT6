Audit Report

## Title
Unchecked Arithmetic Overflow in `denormalize_amount` Permanently Freezes Bridged Funds on Inbound EVM→NEAR Transfers — (File: `near/omni-bridge/src/lib.rs`)

## Summary
`denormalize_amount` performs a bare `*` multiplication of `amount` by `10_u128.pow(diff_decimals)` with no overflow guard. The workspace profile sets `overflow-checks = true`, so a sufficiently large EVM-side transfer amount causes `fin_transfer_callback` to panic unconditionally on every finalization attempt. Because the EVM tokens are already locked or burned before the proof is submitted, the user suffers a permanent, unrecoverable loss of the full transferred value.

## Finding Description
`denormalize_amount` at `near/omni-bridge/src/lib.rs:2776-2779`:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount * (10_u128.pow(diff_decimals))   // ← no checked_mul
}
``` [1](#0-0) 

The workspace release profile explicitly sets `overflow-checks = true`: [2](#0-1) 

This means any overflow in the multiplication is a hard runtime trap (panic/abort), not silent wrapping.

`fin_transfer_callback` calls `denormalize_amount` unconditionally on the amount extracted from the verified EVM proof, before any state mutation that could be rolled back to allow a retry: [3](#0-2) 

`denormalize_fee` also delegates to `denormalize_amount`, so the fee field is a second overflow site in the same callback: [4](#0-3) 

For a NEAR token with `origin_decimals = 24` bridged to an EVM token with `decimals = 18`, `diff_decimals = 6` and the overflow threshold is `u128::MAX / 10^6 ≈ 3.4 × 10^32` in 18-decimal EVM units (≈ 340 trillion whole tokens). The EVM `initTransfer` accepts any `uint128 amount` up to `u128::MAX` with no upper-bound check beyond the caller's balance, so the threshold is reachable for high-supply tokens. Once the EVM transaction is mined, the proof is immutable; every subsequent call to `fin_transfer_callback` with that proof will overflow and revert. There is no admin escape hatch to rescue such a transfer.

The CLAUDE.md false-positive note labelled "Decimal Arithmetic Underflow (NOT a vulnerability)" addresses only the subtraction `origin_decimals - decimals` potentially underflowing when `origin_decimals < decimals`; it does not address multiplication overflow in the `amount * 10^diff_decimals` expression and does not apply here.

## Impact Explanation
Permanent freezing of bridged funds — a concrete match for the Critical allowed impact class. A user who initiates an EVM transfer above the overflow threshold has their tokens irreversibly locked or burned on the EVM side. The corresponding NEAR `fin_transfer_callback` will always trap on overflow, so the tokens can never be claimed on NEAR. No admin function exists to rescue a transfer whose proof causes an arithmetic trap, making the loss total and unrecoverable.

## Likelihood Explanation
Low-to-medium. The overflow threshold in whole tokens is approximately `u128::MAX / 10^origin_decimals`. For NEAR tokens with 24 decimals this is ~340 trillion whole tokens — large but reachable for meme tokens or tokens with very large total supplies. No special role or privileged key is required; any unprivileged user holding a sufficiently large balance of a registered token can trigger this. The risk increases as more high-supply tokens are registered on the bridge.

## Recommendation
Replace the bare `*` with `checked_mul` and propagate the error explicitly:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount
        .checked_mul(10_u128.pow(diff_decimals))
        .near_expect(BridgeError::AmountOverflow)
}
```

Additionally, add a pre-flight validation in `fin_transfer_callback` that rejects proofs whose denormalized amount would exceed `u128::MAX` before any state is mutated, so the relayer receives a clean, actionable error rather than a panic.

## Proof of Concept
1. Register a token with `origin_decimals = 24`, `decimals = 18` (`diff_decimals = 6`).
2. On EVM, call `initTransfer` with `amount = u128::MAX / 10^6 + 1` (≈ 3.4 × 10^32 in 18-decimal units). The EVM transaction succeeds; tokens are locked/burned.
3. A relayer submits the proof to NEAR `fin_transfer`.
4. Inside `fin_transfer_callback`, `denormalize_amount((u128::MAX / 10^6 + 1), decimals)` computes `(u128::MAX / 10^6 + 1) * 10^6`, which overflows `u128`.
5. With `overflow-checks = true` (confirmed in `near/Cargo.toml`): the NEAR runtime traps; the transaction reverts. The proof is valid and can be re-submitted indefinitely, always reverting. The user's EVM tokens are permanently frozen.

A unit test can reproduce this directly:
```rust
#[test]
#[should_panic]
fn test_denormalize_overflow() {
    let decimals = Decimals { origin_decimals: 24, decimals: 18 };
    let amount = u128::MAX / 10_u128.pow(6) + 1;
    Contract::denormalize_amount(amount, decimals); // panics with overflow-checks = true
}
```

### Citations

**File:** near/omni-bridge/src/lib.rs (L722-727)
```rust
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
            fee: Self::denormalize_fee(&init_transfer.fee, decimals),
```

**File:** near/omni-bridge/src/lib.rs (L2776-2779)
```rust
    fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount * (10_u128.pow(diff_decimals))
    }
```

**File:** near/omni-bridge/src/lib.rs (L2790-2795)
```rust
    fn denormalize_fee(fee: &Fee, decimals: Decimals) -> Fee {
        Fee {
            fee: U128(Self::denormalize_amount(fee.fee.0, decimals)),
            native_fee: fee.native_fee,
        }
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
