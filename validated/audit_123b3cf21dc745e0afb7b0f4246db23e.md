Audit Report

## Title
Sub-Unit Transfer Amount Permanently Burns/Locks Tokens With No Recovery Path - (File: near/omni-bridge/src/lib.rs)

## Summary
When a user initiates a NEAR→foreign-chain transfer with an amount smaller than `10^(origin_decimals - decimals)`, `normalize_amount()` returns 0 via integer floor division. Tokens are already burned or locked inside `init_transfer_internal` before this check is applied. The subsequent `sign_transfer` call by the relayer always reverts with `InvalidAmountToTransfer`, and no cancellation or refund path exists, permanently destroying the user's tokens.

## Finding Description

`normalize_amount` performs integer floor division with no guard against a zero result: [1](#0-0) 

For a token with `origin_decimals = 24` and `decimals = 6`, `diff_decimals = 18`. Any `amount < 10^18` normalizes to 0.

The only pre-burn check in `init_transfer` is `fee < amount`: [2](#0-1) 

A dust amount (e.g., `1`) passes this check trivially. After storage validation succeeds, `init_transfer_internal` unconditionally burns or locks the full token amount: [3](#0-2) 

The transfer message is then stored in `pending_transfers` and `U128(0)` is returned, confirming acceptance to the `ft_transfer_call` caller: [4](#0-3) 

Later, when the relayer calls `sign_transfer`, `normalize_amount` is applied to `amount_without_fee()` and the result is checked: [5](#0-4) 

This `require!` panics and reverts only the `sign_transfer` transaction. The original `init_transfer` — which already burned/locked the tokens — is not reverted. No `cancel_transfer`, `rescue_transfer`, or equivalent recovery function exists anywhere in the contract. The transfer message remains in `pending_transfers` indefinitely but can never be signed.

The CLAUDE.md false-positive note (item 2) covers only the case where `origin_decimals < decimals` causes a subtraction underflow panic — it explicitly does not cover the silent-zero case where `amount < 10^diff_decimals`: [6](#0-5) 

The `normalize_amount` doc comment acknowledges that "dust stays locked/burned" when fee = 0, but this refers to sub-unit remainders in otherwise-valid transfers, not the case where the entire normalized amount is zero and the transfer can never complete: [7](#0-6) 

## Impact Explanation

This constitutes permanent, irreversible loss of bridged funds triggered by a normal, unprivileged user action. Tokens are burned (for deployed bridge tokens) or locked in the bridge contract with no recovery path. This matches the allowed critical impact: permanent freezing/loss of bridged funds, and decimal/normalization abuse that changes user balances.

## Likelihood Explanation

The `init_transfer` entry point (`ft_transfer_call` → `ft_on_transfer`) is fully public and requires no special role. Any user who sends a "dust" amount — common in DeFi rounding, programmatic transfers, or UI errors — triggers the loss. For tokens with large decimal gaps (e.g., 24 vs. 6), the minimum safe amount is 1 full token (10^18 base units), a non-obvious constraint with no on-chain enforcement. The condition is repeatable and affects any token pair where `origin_decimals > decimals`.

## Recommendation

Add a minimum-amount guard in `init_transfer` (before `init_transfer_internal` is called) that computes `normalize_amount(amount - fee, decimals)` and returns the full amount to the caller (refund via `ft_transfer_call` returning a non-zero value) if the result is zero. This prevents burning/locking tokens that can never be bridged.

## Proof of Concept

1. Token `foo.near` is registered with `origin_decimals = 24`, `decimals = 6` (diff = 18).
2. User calls `ft_transfer_call` on `foo.near` with `amount = 5×10^17` and a valid `InitTransferMsg` (fee = 0) targeting an EVM recipient.
3. `ft_on_transfer` → `init_transfer` → `init_transfer_internal`:
   - `fee (0) < amount (5×10^17)` passes.
   - Storage check passes.
   - `burn_tokens_if_needed` burns `5×10^17` base units.
   - Transfer stored in `pending_transfers`.
   - Returns `U128(0)` — `ft_transfer_call` sees 0 tokens returned, confirming full acceptance.
4. Relayer calls `sign_transfer` for this transfer ID.
5. `normalize_amount(5×10^17, {24, 6}) = 5×10^17 / 10^18 = 0`.
6. `require!(0 > 0, InvalidAmountToTransfer)` panics → `sign_transfer` reverts.
7. User's `5×10^17` base units are permanently burned. The transfer message is stuck in `pending_transfers` forever with no recovery path.

### Citations

**File:** near/omni-bridge/src/lib.rs (L475-485)
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

**File:** near/omni-bridge/src/lib.rs (L554-557)
```rust
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1850-1857)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
```

**File:** near/omni-bridge/src/lib.rs (L1863-1864)
```rust
        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
        U128(0)
```

**File:** near/omni-bridge/src/lib.rs (L2781-2783)
```rust
    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```

**File:** near/CLAUDE.md (L192-195)
```markdown
**2. Decimal Arithmetic Underflow (NOT a vulnerability)**
- Design expects `origin_decimals >= decimals` (normalization to lower precision)
- Workspace has `overflow-checks = true` in Cargo.toml
- Misconfiguration causes panic (correct fail-safe), not silent corruption
```
