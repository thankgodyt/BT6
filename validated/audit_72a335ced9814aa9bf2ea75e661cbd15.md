Audit Report

## Title
Unchecked Multiplication Overflow in `denormalize_amount` Permanently Freezes Bridged Funds — (File: `near/omni-bridge/src/lib.rs`)

## Summary
`denormalize_amount` performs a bare `u128` multiplication (`amount * 10_u128.pow(diff_decimals)`) with no overflow guard. The workspace release profile sets `overflow-checks = true` and `panic = "abort"`, so any overflow aborts the transaction. When a user bridges a sufficiently large token amount from a foreign chain, the NEAR-side `fin_transfer_callback` calls `denormalize_amount` on the event-supplied amount; if the multiplication overflows, the callback aborts before recording the transfer as finalised, and the tokens already locked or burned on the foreign chain are permanently frozen with no recovery path.

## Finding Description
`denormalize_amount` is defined at `near/omni-bridge/src/lib.rs` lines 2776–2779:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount * (10_u128.pow(diff_decimals))   // bare multiplication, no overflow check
}
``` [1](#0-0) 

The workspace release profile in `near/Cargo.toml` lines 24–31 sets both `overflow-checks = true` and `panic = "abort"`: [2](#0-1) 

This means any integer overflow in release builds traps and aborts the entire transaction rather than wrapping.

`denormalize_amount` is called unconditionally in three places before any state is written:

1. **`fin_transfer_callback`** (line 725) — on the amount and fee from the prover result: [3](#0-2) 

2. **`fast_fin_transfer`** (lines 770–772) — on the fast-path amount and fee: [4](#0-3) 

3. **`claim_fee_callback`** (lines 1122–1127) — on the fee-claim amount: [5](#0-4) 

`denormalize_fee` also delegates to the same function: [6](#0-5) 

**Overflow threshold.** For a token pair where `origin_decimals = 24` (NEAR) and `decimals = 18` (EVM), `diff_decimals = 6`. The multiplication overflows when `amount > u128::MAX / 10^6 ≈ 3.4 × 10^32` raw EVM units, i.e., above ~340 trillion whole tokens. The EVM `initTransfer` accepts `uint128 amount` with no upper-bound guard beyond `fee >= amount`:

```solidity
function initTransfer(address tokenAddress, uint128 amount, ...) external payable {
    if (fee >= amount) { revert InvalidFee(); }
```

There is no maximum-amount check between the EVM deposit and the NEAR callback. Tokens with supplies exceeding this threshold (e.g., SHIB ~589 trillion, PEPE ~420 trillion) exist and are valid `uint128` values on EVM.

**Why existing checks fail.** The `fin_transfer_callback` verifies the emitter factory address and token decimals before calling `denormalize_amount`, but neither check bounds the amount. The abort occurs before `finalised_transfers` is updated, so the transfer is never recorded. Because the amount is immutable in the foreign-chain event, every re-submission of the same proof aborts identically.

## Impact Explanation
This matches the critical allowed impact: **permanent freezing of bridged funds**. Tokens are locked or burned on the EVM side upon `initTransfer`. If `fin_transfer_callback` aborts on every attempt, the transfer is never finalised on NEAR, and there is no refund or rescue path in the EVM bridge for a NEAR-side failure. The funds are irrecoverably frozen.

## Likelihood Explanation
Any unprivileged user who holds a position in a high-supply token registered with `diff_decimals > 0` and bridges an amount above the overflow threshold can trigger this. No special role or key is required; `initTransfer` is publicly callable. The loss is the user's own funds (self-inflicted), but the outcome — permanent, irrecoverable freezing — is within the critical impact scope. The precondition (token supply > ~340 trillion whole tokens with the relevant decimal configuration) is specific but satisfied by real tokens today.

## Recommendation
Replace the bare multiplication in `denormalize_amount` with `checked_mul` and propagate the error:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> Option<u128> {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount.checked_mul(10_u128.pow(diff_decimals))
}
```

At every call site (`fin_transfer_callback`, `fast_fin_transfer`, `claim_fee_callback`), return a descriptive error and reject the transfer if `None` is returned, rather than aborting. Additionally, add a maximum-amount guard in the EVM `initTransfer` function to reject at deposit time any amount that cannot be safely denormalized on NEAR.

## Proof of Concept
1. Register a token pair: EVM token with 18 decimals, NEAR token with 24 decimals (`diff_decimals = 6`).
2. Call `OmniBridge.initTransfer` on EVM with `amount = 3.4 × 10^32 + 1` (a valid `uint128`, above the overflow threshold). Tokens are locked/burned; an `InitTransfer` event is emitted.
3. A relayer submits the proof to NEAR via `fin_transfer`.
4. `fin_transfer_callback` calls `denormalize_amount(3.4 × 10^32 + 1, {decimals: 18, origin_decimals: 24})`.
5. The multiplication `(3.4 × 10^32 + 1) × 10^6` exceeds `u128::MAX`; with `overflow-checks = true` and `panic = "abort"`, the NEAR transaction aborts.
6. The transfer is never recorded in `finalised_transfers`. Every subsequent retry with the same proof aborts identically.
7. The user's tokens on EVM are permanently frozen.

A fuzz test targeting `denormalize_amount` with random `(amount, diff_decimals)` pairs, asserting `amount.checked_mul(10u128.pow(diff_decimals)).is_some()` for all inputs accepted by `initTransfer`, would reproduce the abort path deterministically.

### Citations

**File:** near/omni-bridge/src/lib.rs (L722-732)
```rust
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
            fee: Self::denormalize_fee(&init_transfer.fee, decimals),
            sender: init_transfer.sender,
            msg: init_transfer.msg,
            destination_nonce,
            origin_transfer_id: None,
        };
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
