### Title
Decimal Normalization Truncation to Zero Permanently Freezes User Funds - (`near/omni-bridge/src/lib.rs`)

### Summary

`init_transfer` accepts any amount where `fee < amount`, but does not validate that the normalized amount (after decimal scaling) is non-zero. When a user sends an amount smaller than the decimal normalization factor, their tokens are immediately burned/locked, yet `sign_transfer` will always revert with `InvalidAmountToTransfer` for that transfer, leaving the funds permanently frozen with no recovery path.

### Finding Description

The bridge normalizes token amounts when crossing between chains with different decimal precisions. `normalize_amount` performs floor division: [1](#0-0) 

For a token where `origin_decimals = 24` and `decimals = 18`, the normalization factor is `10^6 = 1,000,000`. Any amount below `1,000,000` base units normalizes to `0`.

`init_transfer` only validates that `fee < amount`: [2](#0-1) 

It does **not** check that `normalize_amount(amount - fee) > 0`. Immediately after this check, tokens are burned or locked: [3](#0-2) 

The function returns `U128(0)`, meaning the NEP-141 standard consumes the full transferred amount (no refund to the caller).

Later, when a relayer calls `sign_transfer`, the normalized amount is computed and checked: [4](#0-3) 

This `require!` always reverts for the affected transfer. The transfer message remains in `pending_transfers` storage indefinitely, and no public cancel/refund function exists to recover the locked tokens.

### Impact Explanation

User funds are permanently frozen in the bridge escrow. The tokens are burned (for deployed bridge tokens) or locked (for native tokens) at `init_transfer` time, but the transfer can never be finalized because `sign_transfer` unconditionally reverts. There is no cancel or refund path for the user to recover their assets.

This matches the allowed impact: **permanent freezing of bridged funds** and **escrow mis-accounting / decimal normalization abuse**.

### Likelihood Explanation

This is reachable by any unprivileged user calling `ft_transfer_call` on NEAR. It is triggered whenever:
1. A token has `origin_decimals > decimals` (e.g., a token registered with 24 origin decimals and 18 NEAR decimals — a common configuration for tokens bridged from chains with higher precision).
2. The user sends `amount_without_fee < 10^(origin_decimals - decimals)` base units.

A user sending a "dust" amount (e.g., 1 base unit of a token with a 6-decimal normalization gap) will silently lose their funds. This can happen accidentally, and no UI-level warning is enforced at the contract level.

### Recommendation

Add a pre-check in `init_transfer` (or `init_transfer_internal`) that validates the normalized amount is non-zero before burning/locking tokens:

```rust
// Before burning/locking, verify the normalized amount is non-zero
let token_address = self.get_token_address(destination_chain, token_id.clone());
if let Some(decimals) = token_address.and_then(|a| self.token_decimals.get(&a)) {
    let normalized = Self::normalize_amount(
        transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
        decimals,
    );
    require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
}
```

Alternatively, enforce a minimum transfer amount at the `ft_on_transfer` entry point based on the token's registered decimal configuration.

### Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (normalization factor = `10^6`).
2. User calls `ft_transfer_call` with `amount = 500_000` (below the factor) and `fee = 0`.
3. `init_transfer` passes the `fee < amount` check (`0 < 500_000` ✓).
4. `init_transfer_internal` burns/locks `500_000` tokens and returns `U128(0)` — tokens consumed.
5. Relayer calls `sign_transfer` for this transfer.
6. `normalize_amount(500_000, Decimals { origin_decimals: 24, decimals: 18 })` = `500_000 / 1_000_000` = `0`.
7. `require!(0 > 0, ...)` → panics with `InvalidAmountToTransfer`.
8. The transfer message stays in `pending_transfers`; the `500_000` tokens are permanently lost.

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

**File:** near/omni-bridge/src/lib.rs (L1850-1858)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
        } else {
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
