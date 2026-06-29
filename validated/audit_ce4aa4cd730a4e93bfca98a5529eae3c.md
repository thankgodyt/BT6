Audit Report

## Title
Decimal Normalization Rounding to Zero After Fee Deduction Permanently Freezes Bridged Funds - (File: near/omni-bridge/src/lib.rs)

## Summary

`init_transfer` accepts and locks/burns a user's tokens after only checking `fee < amount`, with no guard that the post-fee value survives decimal normalization. `sign_transfer` then applies floor-division normalization and panics unconditionally if the result is zero. Because no on-chain cancel or refund path exists, and `update_transfer_fee` only allows fee increases, any transfer where `amount - fee < 10^(origin_decimals - decimals)` results in permanently frozen funds.

## Finding Description

**Root cause — missing pre-normalization guard in `init_transfer`.**

`init_transfer` constructs the `TransferMessage` and validates only:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [1](#0-0) 

`init_transfer_internal` then immediately burns or locks the full `amount`:

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(..., transfer_message.amount.0);
``` [2](#0-1) 

**`sign_transfer` applies normalization and enforces `> 0`.**

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
``` [3](#0-2) 

`normalize_amount` is pure floor-division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [4](#0-3) 

The code comment on `normalize_amount` acknowledges that "when fee = 0, dust stays locked/burned" but this refers to sub-unit remainders, not the complete-zero scenario where the entire `amount - fee` normalizes to zero. [5](#0-4) 

**No on-chain recovery path.**

There is no `cancel_transfer` or refund function in `lib.rs`. `update_transfer_fee` enforces `fee.fee >= current_fee.fee`, meaning the fee can only be raised, which makes `amount - fee` smaller, not larger — the stuck transfer cannot be rescued by fee adjustment. [6](#0-5) 

## Impact Explanation

This is **permanent, irrecoverable freezing of bridged funds**, which matches the allowed critical impact: *"permanent freezing of bridged funds across NEAR, EVM, Solana, Starknet, Bitcoin, Zcash, or Wormhole-routed flows."*

Concrete example with `origin_decimals = 24`, `decimals = 6` (divisor = `10^18`):

| Parameter | Value |
|---|---|
| `amount` | `5` (origin units) |
| `fee` | `0` |
| `fee < amount` check | passes |
| `normalize_amount(5, diff=18)` | `0` |
| `sign_transfer` result | always panics |
| Token fate | permanently locked/burned |

The decimal gap is a protocol-level DAO configuration (`bind_token` / `deploy_token`) invisible to ordinary users. The user receives no on-chain signal at initiation time that the transfer is uncompletable.

## Likelihood Explanation

Any unprivileged user can trigger this via the standard `ft_transfer_call` → `ft_on_transfer` → `init_transfer` flow. No special role or access is required. The condition is met whenever `amount - fee` is below the normalization divisor for a token with a large decimal gap. Accidental triggering (e.g., a user sending a small "test" amount) is realistic. The condition is repeatable for any token registered with `origin_decimals > decimals`.

## Recommendation

Add a normalization-aware guard inside `init_transfer`, before `init_transfer_internal` is called, that mirrors the check already present in `sign_transfer`. Fetch the destination token's `Decimals` from `token_decimals`, compute `normalize_amount(amount - fee, decimals)`, and `require` the result is `> 0`. This rejects the transfer at initiation — before any tokens are moved — rather than silently accepting it and leaving it permanently stuck. [1](#0-0) 

## Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 6` (divisor = `10^18`) via `bind_token` / `deploy_token`.
2. Call `ft_transfer_call` with `amount = 5`, `fee = 0`, valid EVM recipient.
3. Observe: `init_transfer` passes the `fee < amount` check; `init_transfer_internal` locks/burns 5 units; `InitTransferEvent` is emitted.
4. Call `sign_transfer` for the resulting `transfer_id`.
5. Observe: call panics with `ERR_INVALID_AMOUNT_TO_TRANSFER` because `normalize_amount(5, {origin:24, dest:6}) = 5 / 10^18 = 0`.
6. Attempt `update_transfer_fee` to adjust — impossible to make `amount - fee` larger (fee can only increase).
7. Tokens remain permanently locked with no on-chain recovery path.

A local unit test can reproduce this by constructing a `TransferMessage` with the above parameters, calling `init_transfer_internal` directly, then calling `sign_transfer` and asserting the panic string equals `ERR_INVALID_AMOUNT_TO_TRANSFER`. [3](#0-2)

### Citations

**File:** near/omni-bridge/src/lib.rs (L399-402)
```rust
                require!(
                    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
                    BridgeError::InvalidFee.as_ref()
                );
```

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
