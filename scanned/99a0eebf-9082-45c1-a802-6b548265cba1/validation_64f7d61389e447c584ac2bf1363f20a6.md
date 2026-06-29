### Title
Small Transfer Amount Normalizes to Zero, Permanently Freezing User Funds in `sign_transfer` — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

When a user initiates a NEAR→EVM transfer with an amount that, after decimal normalization, rounds down to zero, their tokens are burned or locked during `init_transfer_internal` but `sign_transfer` always panics with `InvalidAmountToTransfer`. There is no cancellation or refund path for the stuck pending transfer, so the user's funds are permanently frozen.

---

### Finding Description

The bridge stores token decimal mappings as a `Decimals { decimals, origin_decimals }` pair. When a NEAR-side token has more decimals than its EVM counterpart (e.g., 24 on NEAR vs. 18 on EVM), the bridge normalizes the amount before signing:

```rust
// near/omni-bridge/src/lib.rs:2784-2787
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

`sign_transfer` calls this and enforces a non-zero result:

```rust
// near/omni-bridge/src/lib.rs:475-485
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
``` [2](#0-1) 

However, `init_transfer` (the entry point) only validates `fee < amount` — it does **not** pre-check that `normalize_amount(amount - fee) > 0`:

```rust
// near/omni-bridge/src/lib.rs:554-557
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [3](#0-2) 

Immediately after this check, `init_transfer_internal` burns (for deployed tokens) or locks (for native tokens) the full amount:

```rust
// near/omni-bridge/src/lib.rs:1850-1857
if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
    self.lock_tokens_if_needed(
        transfer_message.get_destination_chain(),
        &token_id,
        transfer_message.amount.0,
    );
``` [4](#0-3) 

The transfer is then stored in `pending_transfers`. Because `sign_transfer` will always panic for this transfer, and there is no `cancel_transfer` or user-accessible refund path, the funds are permanently frozen.

---

### Impact Explanation

Any user who sends an amount smaller than `10^(origin_decimals − decimals)` (e.g., fewer than `10^6` yocto-units for a 24→18 decimal token) will have their tokens burned or locked with no recovery path. This constitutes **permanent freezing of bridged funds**, which is in the Critical allowed impact scope.

---

### Likelihood Explanation

NEAR tokens commonly use 24 decimals while their EVM counterparts use 18, making the minimum transferable unit `10^6` yocto-tokens. A user sending any amount below this threshold — whether by mistake, UI rounding, or a dust-amount attack — triggers the freeze. No admin action is required; the path is fully user-reachable via `ft_transfer_call`.

---

### Recommendation

Add a normalization check inside `init_transfer` (before burning/locking) to reject transfers whose net amount normalizes to zero:

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

---

### Proof of Concept

1. Token `foo.near` has `origin_decimals = 24` on NEAR and `decimals = 18` on EVM (scaling factor = `10^6`).
2. User calls `ft_transfer_call` with `amount = 500_000` (below `10^6`), `fee = 0`.
3. `init_transfer` passes the `fee < amount` check and calls `init_transfer_internal`.
4. `burn_tokens_if_needed` burns 500,000 units of `foo.near` from the user. [5](#0-4) 
5. Transfer is stored in `pending_transfers`.
6. Relayer calls `sign_transfer`. `normalize_amount(500_000, {24, 18}) = 500_000 / 10^6 = 0`.
7. `require!(amount_to_transfer > 0, ...)` panics — `sign_transfer` always fails. [6](#0-5) 
8. No MPC signature is ever produced; no EVM `finTransfer` can occur.
9. The burned tokens are permanently lost; the pending transfer entry is irremovable.

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

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
