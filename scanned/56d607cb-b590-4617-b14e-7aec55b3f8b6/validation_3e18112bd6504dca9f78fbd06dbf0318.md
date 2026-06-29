### Title
Permanent Freezing of Bridged Funds via Zero Normalized Amount After Decimal Truncation — (`near/omni-bridge/src/lib.rs`)

### Summary

`init_transfer` accepts and locks/burns user tokens for any transfer where `fee < amount`, but does not validate that the net amount after decimal normalization is non-zero. When `normalize_amount(amount - fee)` truncates to zero due to floor division across a decimal gap, every subsequent call to `sign_transfer` permanently panics, leaving the tokens irreversibly burned or locked with no recovery path.

### Finding Description

`init_transfer` enforces only one amount constraint: [1](#0-0) 

This allows a transfer where `amount = 1` and `fee = 0` to pass validation. Immediately after, `init_transfer_internal` burns (for deployed tokens) or locks (for native tokens) the full `amount`: [2](#0-1) 

The transfer is then stored in `pending_transfers`. Later, when `sign_transfer` is called, it computes the normalized amount using floor division: [3](#0-2) 

For a token where `origin_decimals > decimals` (e.g., a NEAR-native token with 24 origin decimals bridging to Ethereum with 18 decimals, giving a divisor of `10^6`), any `amount_without_fee < 10^6` normalizes to zero. `sign_transfer` then unconditionally panics: [4](#0-3) 

There is no `cancel_transfer` or any other recovery function in the contract. The transfer remains in `pending_transfers` forever, and the burned/locked tokens are unrecoverable.

### Impact Explanation

The user's tokens are permanently destroyed or locked. For burned deployed tokens, the supply is reduced with no corresponding release on the destination chain. For locked native tokens, the locked balance is incremented and can never be decremented because `sign_transfer` always panics and `claim_fee` requires a valid on-chain proof of finalization that can never exist. This matches the **permanent freezing of bridged funds** impact class.

### Likelihood Explanation

Any user who sends a "dust" amount of a token whose `origin_decimals` exceeds the destination chain's `decimals` triggers this. For the NEAR→Ethereum path (24 vs 18 decimals), any transfer with `amount_without_fee < 1,000,000 yocto-units` is affected. This is a realistic user error (e.g., sending 1 unit of a high-precision token), and the protocol silently accepts it at `init_transfer` time with no warning.

### Recommendation

Add a validation in `init_transfer` (before burning/locking) that the normalized net amount is non-zero. Specifically, after computing the destination token address and its decimals, assert:

```rust
require!(
    Self::normalize_amount(amount.0 - fee.fee.0, decimals) > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

Alternatively, add a recovery function (analogous to the CLGauge fix of skipping the failing call) that allows the original sender to cancel a pending transfer whose normalized amount is zero and reclaim their tokens.

### Proof of Concept

1. A token is registered with `origin_decimals = 24`, `decimals = 18` (NEAR→Ethereum path).
2. User calls `ft_transfer_call` on the token contract with `amount = 500_000` (< 10^6) and `msg` encoding `InitTransferMsg { fee: U128(0), ... }`.
3. `init_transfer` passes the `fee < amount` check (`0 < 500_000`). [1](#0-0) 
4. `init_transfer_internal` burns the 500,000 units and stores the transfer in `pending_transfers`. [2](#0-1) 
5. Relayer calls `sign_transfer`. `normalize_amount(500_000, {decimals:18, origin_decimals:24})` = `500_000 / 1_000_000 = 0`. [3](#0-2) 
6. `require!(0 > 0, ...)` panics. The call reverts. [4](#0-3) 
7. No recovery path exists. The 500,000 units are permanently burned and the transfer is stuck in `pending_transfers` indefinitely.

### Citations

**File:** near/omni-bridge/src/lib.rs (L482-485)
```rust
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
