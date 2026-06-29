### Title
`sign_transfer` Panics with `InvalidAmountToTransfer` When `normalize_amount` Rounds to Zero, Permanently Locking User Tokens — (`near/omni-bridge/src/lib.rs`)

### Summary

In `sign_transfer()`, the amount to transfer is computed by applying `normalize_amount()` (floor division) to `amount_without_fee`. If the result is zero, the function panics. Because the user's tokens are already locked or burned in a prior, committed transaction (`init_transfer_internal`), and no cancel/refund mechanism exists for pending transfers, the tokens are permanently frozen in the bridge.

### Finding Description

`sign_transfer` computes the on-chain transfer amount as follows:

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
``` [1](#0-0) 

`normalize_amount` performs floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [2](#0-1) 

`amount_without_fee` is simply `amount - fee`:

```rust
pub fn amount_without_fee(&self) -> Option<u128> {
    self.amount.0.checked_sub(self.fee.fee.0)
}
``` [3](#0-2) 

If `amount_without_fee < 10^(origin_decimals - decimals)`, floor division yields 0 and `sign_transfer` panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`. This panic happens in a **separate transaction** from the one that locked the tokens.

The token lock/burn happens in `init_transfer_internal`, which runs during `ft_on_transfer` (the user's deposit transaction):

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(
    transfer_message.get_destination_chain(),
    &token_id,
    transfer_message.amount.0,
);
``` [4](#0-3) 

The `sign_transfer` panic does **not** revert the token lock — it is a different transaction. The transfer message remains in `pending_transfers` indefinitely. There is no `cancel_transfer` or refund function in the contract. `update_transfer_fee` only allows increasing the fee (making `amount_without_fee` smaller, not larger), so the user cannot self-rescue. [5](#0-4) 

### Impact Explanation

**Permanent freezing of bridged funds.** A user who deposits a token amount that, after fee deduction, is smaller than `10^(origin_decimals - decimals)` will have their tokens locked in the bridge forever. For a token with `origin_decimals = 24` and `decimals = 18` (a common NEAR-to-EVM pairing), the threshold is 1,000,000 base units. Any transfer where `amount - fee < 1,000,000` will trigger this path. The tokens cannot be recovered because:

1. The lock/burn is committed in the user's transaction.
2. `sign_transfer` always panics for this transfer ID.
3. No cancel or admin-refund path exists in the contract.

### Likelihood Explanation

Moderate. The condition is triggered whenever a user (or a relayer on their behalf) initiates a transfer where `amount_without_fee` is below the decimal-normalization threshold. This is not an exotic edge case: for tokens with a 6-decimal difference (e.g., NEAR's 24 vs ETH's 18), any transfer of fewer than 1,000,000 base units net of fee hits this path. Users are not warned of this constraint at deposit time, and the `init_transfer` validation only checks `fee < amount`, not that `normalize_amount(amount - fee) > 0`. [6](#0-5) 

### Recommendation

Add the normalization check **before** locking tokens, inside `init_transfer` or `init_transfer_internal`, so the deposit is rejected (and tokens returned) rather than accepted and then permanently frozen:

```rust
// In init_transfer, after building transfer_message:
let token_address = self.get_token_address(...);
let decimals = self.token_decimals.get(&token_address)...;
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

This mirrors the fix in the external report: move the threshold check to the point where a graceful rejection (token refund) is still possible, rather than panicking after the funds are already committed.

### Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (diff = 6, divisor = 1,000,000).
2. User calls `ft_transfer_call` with `amount = 500_000`, `fee = 0`.
3. `init_transfer` passes (`fee < amount` ✓). Tokens are locked. Transfer message stored.
4. Relayer calls `sign_transfer` for this transfer ID.
5. `normalize_amount(500_000, {24, 18}) = 500_000 / 1_000_000 = 0`.
6. `require!(0 > 0, ...)` → panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
7. User's 500,000 tokens remain locked in the bridge with no recovery path. [1](#0-0) [2](#0-1)

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

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```

**File:** near/omni-types/src/lib.rs (L593-595)
```rust
    pub fn amount_without_fee(&self) -> Option<u128> {
        self.amount.0.checked_sub(self.fee.fee.0)
    }
```
