Audit Report

## Title
Small Transfer Amount Normalizes to Zero, Permanently Freezing User Funds in `sign_transfer` — (File: `near/omni-bridge/src/lib.rs`)

## Summary
When a user initiates a NEAR→EVM transfer with an amount that normalizes to zero after decimal scaling, `init_transfer_internal` burns or locks the full token amount and stores the transfer in `pending_transfers`. However, `sign_transfer` unconditionally panics with `InvalidAmountToTransfer` for such transfers, and no user-accessible cancellation or refund path exists, permanently freezing the funds.

## Finding Description
`normalize_amount` uses floor division to scale amounts from NEAR decimals to EVM decimals:

```rust
// near/omni-bridge/src/lib.rs:2784-2787
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

For a token with `origin_decimals = 24` and `decimals = 18`, any amount below `10^6` normalizes to zero. `sign_transfer` enforces a non-zero result:

```rust
// near/omni-bridge/src/lib.rs:475-485
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
``` [2](#0-1) 

`init_transfer` only validates `fee < amount` — it does not pre-check that `normalize_amount(amount - fee) > 0`: [3](#0-2) 

After this insufficient check, `init_transfer_internal` immediately burns (for deployed tokens) or locks (for native tokens) the full amount: [4](#0-3) 

`burn_tokens_if_needed` fires a detached cross-contract call — the burn is irrevocable: [5](#0-4) 

The only internal removal function is `remove_transfer_message_without_refund`, which is private and not exposed to users. No public `cancel_transfer` or equivalent exists. The code comment at L2781–2782 acknowledges that "dust stays locked/burned" but this refers to sub-unit remainders, not to the entire transfer amount normalizing to zero — a materially worse case with no documented exclusion. [6](#0-5) 

## Impact Explanation
Any user sending an amount below the decimal scaling threshold (e.g., fewer than `10^6` yocto-units for a 24→18 decimal token) has their tokens permanently burned or locked. The pending transfer entry is irremovable by the user, and no MPC signature can ever be produced for it. This constitutes **permanent freezing of bridged funds**, matching the Critical allowed impact scope.

## Likelihood Explanation
NEAR tokens commonly use 24 decimals while their EVM counterparts use 18, making the minimum transferable unit `10^6` yocto-tokens. Any user sending below this threshold — by mistake, UI rounding error, or intentional dust — triggers the freeze. The path is fully reachable via the public `ft_transfer_call` entry point with no privileged access required.

## Recommendation
Add a normalization check inside `init_transfer` (before `init_transfer_internal` is called) to reject transfers whose net amount normalizes to zero:

```rust
let token_address = self.get_token_address(destination_chain, token_id.clone())
    .near_expect(BridgeError::FailedToGetTokenAddress);
let decimals = self.token_decimals.get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);
require!(
    Self::normalize_amount(amount_without_fee, decimals) > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

This mirrors the guard already present in `sign_transfer` and prevents tokens from being burned/locked for a transfer that can never be finalized.

## Proof of Concept
1. Token `foo.near` has `origin_decimals = 24` on NEAR and `decimals = 18` on EVM (scaling factor = `10^6`).
2. User calls `ft_transfer_call` with `amount = 500_000`, `fee = 0`.
3. `init_transfer` passes the `fee < amount` check (0 < 500_000) and calls `init_transfer_internal`.
4. `burn_tokens_if_needed` fires a detached burn of 500,000 units of `foo.near`.
5. Transfer is stored in `pending_transfers`.
6. Relayer calls `sign_transfer`. `normalize_amount(500_000, {24, 18}) = 500_000 / 10^6 = 0`.
7. `require!(amount_to_transfer > 0, ...)` panics — `sign_transfer` always fails for this transfer.
8. No MPC signature is produced; no EVM `finTransfer` can occur.
9. The burned tokens are permanently lost; the pending transfer entry is irremovable by the user.

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

**File:** near/omni-bridge/src/lib.rs (L1806-1812)
```rust
    fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
        if self.is_deployed_token(&token) {
            ext_token::ext(token)
                .with_static_gas(BURN_TOKEN_GAS)
                .burn(amount)
                .detach();
        }
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
