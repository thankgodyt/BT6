Audit Report

## Title
`denormalize_amount` Unchecked Multiplication Overflow Permanently Freezes Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

## Summary
The `denormalize_amount` helper performs a bare `u128` multiplication without overflow protection. With `overflow-checks = true` set in the workspace release profile, an oversized transfer amount causes `fin_transfer_callback` to panic after the source-chain tokens are already locked or burned on EVM, permanently freezing those funds until a DAO-approved contract upgrade is deployed.

## Finding Description
`denormalize_amount` at line 2776–2779 performs an unchecked multiplication:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount * (10_u128.pow(diff_decimals))   // panics on overflow
}
```

The workspace `near/Cargo.toml` at line 31 explicitly sets `overflow-checks = true` under `[profile.release]`, so Rust inserts a runtime overflow check on every integer arithmetic operation. Combined with `panic = "abort"` at line 30, any overflow aborts the transaction.

In `fin_transfer_callback` (lines 722–725), `denormalize_amount` is called unconditionally while constructing `transfer_message`, before any state mutation records the transfer as finalised:

```rust
let transfer_message = TransferMessage {
    ...
    amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
    ...
};
```

`add_fin_transfer` (which inserts into `finalised_transfers`) is only called later inside `process_fin_transfer_to_near` at line 1875. Because the panic occurs before this point, the transfer ID is never recorded as finalised. The source-chain EVM `initTransfer` has already been mined and the tokens locked or burned; the proof cannot be successfully resubmitted against the unmodified contract.

The same unchecked call appears in `fast_fin_transfer` (lines 770–771) and `claim_fee_callback` (lines 1122–1127).

## Impact Explanation
This directly matches the allowed critical impact: **permanent freezing of bridged funds**. For a token registered with 18 EVM decimals and 24 NEAR decimals (`diff_decimals = 6`), the overflow threshold is `u128::MAX / 10^6 / 10^18 ≈ 340 trillion whole tokens`. Tokens such as SHIB (~589 trillion total supply) and PEPE (~420 trillion total supply) have per-holder amounts that can exceed this threshold. Any such transfer causes the NEAR callback to abort, leaving the EVM-side burn irreversible and the funds permanently frozen.

## Likelihood Explanation
No privileged role is required. The attacker-controlled input is the `amount` field of the EVM `initTransfer` call, which is a user-supplied `uint128`. A holder of a sufficiently large balance of a high-supply meme token (a realistic condition given SHIB/PEPE distribution) can trigger this path either accidentally or deliberately. The relayer acts correctly; the overflow is entirely a function of the user-supplied amount and the registered decimal configuration.

## Recommendation
Replace the bare multiplication in `denormalize_amount` with a checked variant and propagate the error:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> Result<u128, BridgeError> {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    let multiplier = 10_u128.pow(diff_decimals);
    amount.checked_mul(multiplier).ok_or(BridgeError::AmountOverflow)
}
```

Propagate the `Result` in `fin_transfer_callback`, `fast_fin_transfer`, and `claim_fee_callback` so that an oversized amount causes a clean, recoverable rejection (returning an error or refunding) rather than a panic. This prevents source-chain tokens from being locked without a corresponding NEAR-side finalisation record.

## Proof of Concept
Token registered with `decimals = 18` (EVM), `origin_decimals = 24` (NEAR), giving `diff_decimals = 6`.

1. User holds `4 × 10^32` EVM token units (~400 trillion whole tokens, within SHIB-class supply).
2. User calls `initTransfer` on the EVM bridge with `amount = 4 × 10^32`. EVM bridge burns tokens and emits `InitTransfer`.
3. Relayer submits the proof to the NEAR bridge via `fin_transfer`.
4. `fin_transfer_callback` executes `denormalize_amount(4e32, Decimals { decimals: 18, origin_decimals: 24 })`:
   - `4e32 * 10^6 = 4e38`
   - `u128::MAX ≈ 3.4e38 < 4e38` → **overflow panic / abort**
5. NEAR callback aborts. `finalised_transfers` is not updated.
6. EVM burn is irreversible. Funds are permanently frozen until a DAO-approved contract upgrade.

A fuzz test targeting `denormalize_amount` with amounts in the range `[u128::MAX / 10^diff_decimals, u128::MAX]` will reproduce the panic deterministically. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** near/omni-bridge/src/lib.rs (L722-725)
```rust
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
```

**File:** near/omni-bridge/src/lib.rs (L770-771)
```rust
        let denormalized_amount =
            Self::denormalize_amount(fast_fin_transfer_msg.amount.0, decimals);
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

**File:** near/omni-bridge/src/lib.rs (L1875-1875)
```rust
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());
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
