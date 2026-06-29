Audit Report

## Title
`sign_transfer` Panics with `InvalidAmountToTransfer` After Tokens Are Irreversibly Locked, Causing Permanent Fund Freeze — (`near/omni-bridge/src/lib.rs`)

## Summary

When a user initiates a transfer with an `amount_without_fee` below the decimal-normalization threshold, tokens are locked/burned in `init_transfer_internal` in one transaction, but `sign_transfer` subsequently panics with `ERR_INVALID_AMOUNT_TO_TRANSFER` in a separate transaction. Because no cancel or refund path exists and `update_transfer_fee` can only increase the fee (making recovery impossible), the user's tokens are permanently frozen in the bridge.

## Finding Description

The root cause is a missing pre-lock validation: `init_transfer_internal` only checks `fee.fee < amount` before locking tokens, but does not verify that `normalize_amount(amount - fee) > 0`.

**Lock happens unconditionally in `init_transfer_internal`:** [1](#0-0) 

**The only fee validation before locking:** [2](#0-1) 

**`sign_transfer` (a separate transaction) then computes the normalized amount and panics if it is zero:** [3](#0-2) 

**`normalize_amount` uses floor division:** [4](#0-3) 

For a token with `origin_decimals = 24` and `decimals = 18`, the divisor is `10^6 = 1,000,000`. Any `amount_without_fee < 1,000,000` normalizes to 0 and causes the panic.

**No recovery path exists:** `cancel_transfer` does not exist in the contract (grep confirms zero matches). `update_transfer_fee` enforces `fee.fee >= current_fee.fee`, meaning the fee can only be raised, which shrinks `amount_without_fee` further and makes the situation worse, not better: [5](#0-4) 

The `normalize_amount` comment itself acknowledges that "dust stays locked/burned" when fee is 0, but this applies to remainders — the vulnerability is the entire `amount_without_fee` rounding to zero: [6](#0-5) 

## Impact Explanation

This is a **permanent freezing of bridged funds**, matching the Critical allowed impact: *"permanent freezing of bridged funds across NEAR, EVM, Solana, Starknet, Bitcoin, Zcash, or Wormhole-routed flows."* The user's tokens are locked in the bridge contract with no on-chain mechanism to recover them. The transfer message remains in `pending_transfers` indefinitely, and `sign_transfer` will always panic for that transfer ID.

## Likelihood Explanation

Any unprivileged user can trigger this by calling `ft_transfer_call` with a small amount. For the common NEAR-to-EVM pairing (`origin_decimals = 24`, `decimals = 18`), any net transfer below 1,000,000 base units hits this path. The user is not warned at deposit time, and the `init_transfer` validation does not catch this condition. The relayer calling `sign_transfer` is performing its expected role; the panic is deterministic and repeatable for the affected transfer ID.

## Recommendation

Add the normalization check **before** locking tokens, inside `init_transfer_internal` (or `init_transfer`), so the deposit is rejected and tokens are returned rather than accepted and permanently frozen:

```rust
// After building transfer_message, before burn_tokens_if_needed / lock_tokens_if_needed:
let token_address = self.get_token_address(...);
let decimals = self.token_decimals.get(&token_address)
    .near_expect(BridgeError::TokenDecimalsNotFound);
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This mirrors the existing check in `sign_transfer` but moves it to the point where a graceful rejection (token refund via `ft_on_transfer` return value) is still possible.

## Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (divisor = 1,000,000).
2. User calls `ft_transfer_call` with `amount = 500_000`, `fee = 0`.
3. `init_transfer` passes (`fee < amount` ✓). Tokens are locked. Transfer message stored.
4. Relayer calls `sign_transfer` for this transfer ID.
5. `normalize_amount(500_000, {24, 18}) = 500_000 / 1_000_000 = 0`.
6. `require!(0 > 0, ...)` → panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
7. User's 500,000 tokens remain locked with no recovery path.

A local unit test can reproduce this by: (a) registering a token with the above decimals, (b) calling `ft_on_transfer` with the small amount, (c) asserting the transfer message is stored, (d) calling `sign_transfer` and asserting it panics, (e) asserting the token balance of the bridge contract has not decreased.

### Citations

**File:** near/omni-bridge/src/lib.rs (L399-401)
```rust
                require!(
                    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
                    BridgeError::InvalidFee.as_ref()
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

**File:** near/omni-bridge/src/lib.rs (L2781-2787)
```rust
    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
