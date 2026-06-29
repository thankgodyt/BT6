### Title
Small-Amount Transfer Permanently Burns/Locks User Tokens With No Recovery Path - (`near/omni-bridge/src/lib.rs`)

### Summary
When a user initiates a NEAR→foreign-chain transfer with an amount smaller than `10^(origin_decimals - decimals)`, the `normalize_amount()` function returns 0 due to integer floor division. The tokens are already burned or locked in the `init_transfer` step, but the subsequent `sign_transfer` call by the relayer will always revert with `InvalidAmountToTransfer`. There is no cancellation or refund path, so the user's tokens are permanently lost.

### Finding Description

`normalize_amount` performs integer floor division: [1](#0-0) 

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

For a token with `origin_decimals = 24` (NEAR standard) and `decimals = 6` (EVM USDC-like), `diff_decimals = 18`. Any `amount < 10^18` normalizes to 0.

The user's tokens are burned/locked inside `init_transfer_internal`, which is called unconditionally once storage checks pass: [2](#0-1) 

```rust
if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
    self.lock_tokens_if_needed(
        transfer_message.get_destination_chain(),
        &token_id,
        transfer_message.amount.0,
    );
```

There is no minimum-amount guard in `init_transfer`: [3](#0-2) 

Only `fee < amount` is checked. A deposit of, e.g., `1` yoctoNEAR-unit of a 24-decimal token passes this check.

Later, when the relayer calls `sign_transfer`, `normalize_amount` is applied to `amount_without_fee()` and the result is checked: [4](#0-3) 

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee()...
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

This `require!` panics and reverts only the `sign_transfer` transaction. The original `init_transfer` transaction — which already burned/locked the tokens — is not reverted. The transfer message stays in `pending_transfers` indefinitely but can never be signed. There is no `cancel_transfer` or rescue function in the contract.

The false-positive note in `CLAUDE.md` (item 2) covers only the case where `origin_decimals < decimals` causes a subtraction underflow panic — it does not cover the silent-zero case where `amount < 10^diff_decimals`. [5](#0-4) 

### Impact Explanation

A user who deposits fewer than `10^(origin_decimals - decimals)` base units of a token (e.g., any sub-unit amount of a 24-decimal NEAR token bridging to a 6-decimal EVM token) permanently loses those tokens. The tokens are burned (for deployed bridge tokens) or locked in the bridge contract with no recovery path. This constitutes a permanent, irreversible loss of bridged funds triggered by a normal, unprivileged user action.

### Likelihood Explanation

The `init_transfer` entry point (`ft_transfer_call` → `ft_on_transfer`) is fully public and requires no special role. Any user who sends a "dust" amount — which is common in DeFi interactions, rounding, or programmatic transfers — triggers the loss. For tokens with large decimal gaps (e.g., 24 vs. 6), the minimum safe amount is 1 full token (10^18 base units), which is a non-obvious constraint with no on-chain enforcement.

### Recommendation

Add a minimum-amount guard in `init_transfer` (or `init_transfer_internal`) that checks whether `normalize_amount(amount_without_fee, decimals) > 0` before burning or locking tokens. If the normalized amount would be zero, return the full amount to the caller (refund) rather than proceeding.

### Proof of Concept

1. Token `foo.near` is registered with `origin_decimals = 24`, `decimals = 6` (diff = 18).
2. User calls `ft_transfer_call` on `foo.near` with `amount = 500_000_000_000_000_000` (5 × 10^17, i.e., 0.5 tokens in 24-decimal representation) and a valid `InitTransferMsg` targeting an EVM recipient.
3. `ft_on_transfer` → `init_transfer` → `init_transfer_internal`:
   - Storage check passes.
   - `burn_tokens_if_needed` burns 5 × 10^17 base units from the user.
   - Transfer message stored in `pending_transfers`.
   - Returns `U128(0)` — user's `ft_transfer_call` sees 0 tokens returned, confirming acceptance.
4. Relayer calls `sign_transfer` for this transfer ID.
5. `normalize_amount(5e17, Decimals { origin_decimals: 24, decimals: 6 }) = 5e17 / 1e18 = 0`.
6. `require!(0 > 0, ...)` panics → `sign_transfer` reverts.
7. User's 5 × 10^17 base units are permanently burned. The transfer message is stuck in `pending_transfers` forever.

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
