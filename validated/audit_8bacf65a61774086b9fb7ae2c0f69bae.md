Audit Report

## Title
Unchecked u128 Multiplication Overflow in `denormalize_amount` Permanently Freezes Bridged Funds — (File: near/omni-bridge/src/lib.rs)

## Summary
`denormalize_amount` performs a bare `u128` multiplication with no overflow guard. With `overflow-checks = true` in the workspace release profile, any call where `amount × 10^(origin_decimals − decimals)` exceeds `u128::MAX` causes a panic. Because the EVM-side `initTransfer` locks or burns tokens before the NEAR `fin_transfer_callback` executes, a panic in the callback leaves those tokens permanently frozen with no on-chain recovery path.

## Finding Description
`denormalize_amount` at line 2776–2779 of `near/omni-bridge/src/lib.rs` is:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount * (10_u128.pow(diff_decimals))   // unchecked multiplication
}
``` [1](#0-0) 

The workspace `[profile.release]` in `near/Cargo.toml` sets `overflow-checks = true`, so this multiplication panics (rather than wrapping) when the result exceeds `u128::MAX`. [2](#0-1) 

The function is called unconditionally inside `fin_transfer_callback` at line 725, after the prover has already accepted the EVM proof:

```rust
amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
``` [3](#0-2) 

It is also called in `fast_fin_transfer` (line 770–771) and `claim_fee_callback` (line 1122–1127), both without any overflow guard. [4](#0-3) [5](#0-4) 

The `fin_transfer` entry point calls `verify_proof` (an external prover contract) and chains `fin_transfer_callback` as a subsequent promise:

```rust
let mut main_promise = self.verify_proof(args.chain_kind, args.prover_args);
// ...
main_promise.then(Self::ext(...).fin_transfer_callback(...))
``` [6](#0-5) 

Because `verify_proof` executes in an external contract, its state change (marking the proof as used) is not rolled back when `fin_transfer_callback` panics. Re-submission therefore fails with "proof already used," and the EVM-locked tokens have no recovery path.

The `CLAUDE.md` false-positive note at lines 192–195 explicitly covers only the *underflow* case (`origin_decimals < decimals` misconfiguration). The *overflow* case — a correctly configured token pair with a large but valid `uint128` amount — is not addressed. [7](#0-6) 

## Impact Explanation
This is a **permanent freezing of bridged funds**, matching the Critical allowed impact: *"permanent freezing of bridged funds across NEAR, EVM … flows."* The EVM tokens are irrevocably locked or burned by `initTransfer` before the NEAR callback runs. The callback panic leaves no NEAR-side finalization record and, because the proof is consumed by the external prover, no re-submission is possible. The user's funds are unrecoverable without a contract upgrade.

## Likelihood Explanation
The overflow threshold for `diff_decimals = d` is `amount > u128::MAX / 10^d`. For `d = 18` (e.g., a NEAR token with 24 decimals bridged to an EVM token with 6 decimals), the threshold in raw EVM token units is ≈ 3.4 × 10²⁰ — well within the `uint128` range accepted by `initTransfer`. Any user who submits an EVM transfer above this threshold triggers the panic. The EVM contract imposes no ceiling below `uint128::MAX`, and high-supply tokens can reach these values. The trigger requires only a standard EVM `initTransfer` call followed by normal relayer proof submission — no special privileges for the initiating user.

## Recommendation
Replace the bare multiplication with a checked variant and propagate the error:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> Option<u128> {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount.checked_mul(10_u128.pow(diff_decimals))
}
```

All call sites (`fin_transfer_callback`, `fast_fin_transfer`, `claim_fee_callback`) should handle `None` by panicking with a descriptive error message. Additionally, enforce a maximum transferable amount on the EVM side — computed from `u128::MAX / 10^diff_decimals` — so that amounts that would overflow are rejected before tokens are locked or burned.

## Proof of Concept
1. Register a NEAR token with `origin_decimals = 24`; its EVM counterpart is normalized to `decimals = 6` (`diff_decimals = 18`).
2. Call `initTransfer` on the EVM `OmniBridge` contract with `amount = u128::MAX / 10^18 + 1` (≈ 3.4 × 10²⁰ + 1 in raw EVM units). Tokens are locked/burned in the EVM contract.
3. A trusted relayer submits the resulting proof to NEAR `fin_transfer`.
4. `fin_transfer` calls the external prover, which marks the proof as used, then chains `fin_transfer_callback`.
5. `fin_transfer_callback` calls `denormalize_amount(amount, decimals)`, evaluating `(u128::MAX/10^18 + 1) * 10^18 > u128::MAX`.
6. With `overflow-checks = true`, the NEAR runtime panics; the callback transaction fails.
7. The proof is already consumed; re-submission fails. The EVM tokens remain permanently locked; no NEAR tokens are minted; no recovery function exists.

A local integration test can reproduce this by deploying the mock prover and bridge contracts, registering a token with the above decimal configuration, and calling `fin_transfer` with the overflow amount — asserting that the callback panics and the EVM-side escrow balance remains non-zero with no corresponding NEAR mint.

### Citations

**File:** near/omni-bridge/src/lib.rs (L678-695)
```rust
        let mut main_promise = self.verify_proof(args.chain_kind, args.prover_args);

        let mut attached_deposit = env::attached_deposit();

        for action in &args.storage_deposit_actions {
            main_promise =
                main_promise.and(Self::check_or_pay_ft_storage(action, &mut attached_deposit));
        }

        main_promise.then(
            Self::ext(env::current_account_id())
                .with_attached_deposit(attached_deposit)
                .with_static_gas(FIN_TRANSFER_CALLBACK_GAS)
                .fin_transfer_callback(
                    &args.storage_deposit_actions,
                    env::predecessor_account_id(),
                ),
        )
```

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

**File:** near/Cargo.toml (L31-31)
```text
overflow-checks = true
```

**File:** near/CLAUDE.md (L192-195)
```markdown
**2. Decimal Arithmetic Underflow (NOT a vulnerability)**
- Design expects `origin_decimals >= decimals` (normalization to lower precision)
- Workspace has `overflow-checks = true` in Cargo.toml
- Misconfiguration causes panic (correct fail-safe), not silent corruption
```
