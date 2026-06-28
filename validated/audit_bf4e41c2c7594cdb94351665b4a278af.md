### Title
Decimal Normalization Rounding to Zero Permanently Locks User Tokens Without Recovery - (`near/omni-bridge/src/lib.rs`)

### Summary

In the NEAR → Foreign transfer flow, `init_transfer` accepts and locks/burns user tokens before any check that the normalized transfer amount is non-zero. The zero-amount guard exists only in `sign_transfer`, which is called later by a relayer. When `normalize_amount(amount - fee)` rounds to zero due to decimal precision differences, the tokens are permanently locked with no cancellation or refund path.

### Finding Description

`normalize_amount` uses floor division to scale a NEAR-side token amount down to the destination chain's decimal precision: [1](#0-0) 

When a user initiates a NEAR → Foreign transfer via `ft_on_transfer` → `init_transfer`, the only validation on the amount is: [2](#0-1) 

This check only ensures `fee < amount`, not that `normalize_amount(amount - fee) > 0`. Immediately after, `init_transfer_internal` burns or locks the full token amount: [3](#0-2) 

The zero-amount guard exists only in `sign_transfer`, called later by a relayer: [4](#0-3) 

If `normalize_amount(amount - fee) == 0`, `sign_transfer` always panics with `InvalidAmountToTransfer`. The transfer message remains stored in state, the tokens remain locked/burned, and there is no public cancel or refund function to recover them.

### Impact Explanation

A user who sends a token amount smaller than `10^(origin_decimals - decimals)` will have their tokens permanently locked in the bridge escrow (or burned if it is a deployed bridge token) with no recovery path. For example, for a NEAR-native token with 24 decimals bridged to an EVM chain where it has 18 decimals (`diff = 6`), any amount below `1_000_000` units normalizes to zero. The tokens are irrecoverably lost.

This is a permanent, irreversible loss of bridged funds — fitting the critical impact scope of "escrow mis-accounting / decimal normalization abuse that changes user balances."

### Likelihood Explanation

Any unprivileged user can trigger this by calling `ft_on_transfer` on the bridge contract with a sufficiently small token amount. The entry point is fully public. For tokens with a large decimal difference between NEAR and the destination chain (e.g., NEAR's native 24-decimal token bridged to an 18-decimal EVM representation), the threshold below which amounts round to zero is non-trivial (1,000,000 units). A user could trigger this accidentally or be socially engineered into it.

### Recommendation

Add a zero-amount check in `init_transfer` (or `init_transfer_internal`) before locking/burning tokens, analogous to the check already present in `sign_transfer`:

```rust
let token_address = self.get_token_address(
    transfer_message.get_destination_chain(),
    self.get_token_id(&transfer_message.token),
);
if let Some(token_address) = token_address {
    if let Some(decimals) = self.token_decimals.get(&token_address) {
        let normalized = Self::normalize_amount(
            transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
            decimals,
        );
        require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
    }
}
```

Alternatively, reject the transfer in `init_transfer` before any state mutation if the normalized amount would be zero.

### Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (diff = 6).
2. Call `ft_on_transfer` on the bridge with `amount = 500_000` (less than `10^6`) and `fee = 0`, targeting an EVM recipient.
3. `init_transfer` passes the `fee < amount` check (0 < 500_000). [2](#0-1) 
4. `init_transfer_internal` burns/locks the 500,000 tokens. [3](#0-2) 
5. A relayer calls `sign_transfer`. `normalize_amount(500_000, {origin: 24, dest: 18}) = 500_000 / 1_000_000 = 0`. [1](#0-0) 
6. `require!(amount_to_transfer > 0, ...)` panics. [5](#0-4) 
7. The transfer message remains in state. The 500,000 tokens are permanently lost with no cancel or refund mechanism available.

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
