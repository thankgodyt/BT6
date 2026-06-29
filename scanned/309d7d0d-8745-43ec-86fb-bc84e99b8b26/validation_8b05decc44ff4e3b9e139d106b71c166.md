### Title
Decimal Normalization Floor Division Permanently Freezes Bridged Funds When `normalize_amount(amount_without_fee)` Rounds to Zero - (`near/omni-bridge/src/lib.rs`)

### Summary

The `init_transfer` path accepts and locks user tokens without validating that the post-normalization transferable amount is non-zero. When `normalize_amount(amount_without_fee())` rounds to zero due to floor division, `sign_transfer` permanently panics with `InvalidAmountToTransfer`, and no cancel or refund path exists. The locked tokens are irrecoverable.

### Finding Description

`normalize_amount` performs floor division to convert a NEAR-side token amount to its destination-chain representation:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

The code comment explicitly acknowledges: *"When fee = 0, dust stays locked/burned."* [2](#0-1) 

`init_transfer` stores the transfer message and locks the user's tokens after only checking `fee.fee < amount`:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [3](#0-2) 

It does **not** validate that `normalize_amount(amount_without_fee())` > 0. Later, when a relayer calls `sign_transfer`, the normalized amount is computed and checked:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
``` [4](#0-3) 

`amount_without_fee()` is a simple subtraction:

```rust
pub fn amount_without_fee(&self) -> Option<u128> {
    self.amount.0.checked_sub(self.fee.fee.0)
}
``` [5](#0-4) 

If `amount_without_fee()` is positive but less than `10^(origin_decimals - decimals)`, `normalize_amount` returns 0 and `sign_transfer` always panics. There is no cancel-transfer or user-refund function; `remove_transfer_message` is only reachable via `claim_fee_callback` (requires a finalization proof from the destination chain) or `fin_transfer_send_tokens_callback` (requires a successful token send). Neither is reachable when `sign_transfer` is permanently blocked. [6](#0-5) 

`update_transfer_fee` cannot rescue the transfer either — it only allows the fee to be **increased**, which further reduces `amount_without_fee()`:

```rust
require!(
    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [7](#0-6) 

### Impact Explanation

Any user tokens locked by `init_transfer` where `normalize_amount(amount_without_fee())` = 0 are permanently frozen in the bridge contract. This satisfies the **Critical** impact category: *permanent freezing of bridged funds*.

Concrete example with a token registered as `origin_decimals = 24`, `decimals = 18` (6-decimal difference, divisor = 1,000,000):

- User sends 999,999 units with fee = 0 → `normalize_amount(999,999)` = 0 → tokens locked forever.
- User sends 1,500,000 units with fee = 1,000,000 → `amount_without_fee()` = 500,000 → `normalize_amount(500,000)` = 0 → tokens locked forever.

NEAR-native tokens (24 decimals) bridged to EVM chains (18 decimals) are a real production case.

### Likelihood Explanation

The condition is reachable by any unprivileged user calling `ft_transfer_call` with a small amount or a high fee. No special role or permission is required. The decimal gap between NEAR (24 decimals) and EVM chains (18 decimals) is a standard production configuration, making the minimum-unit threshold 1,000,000 NEAR-side units — a realistic amount for low-value or dust transfers. Users may also accidentally trigger this by setting a fee that leaves a sub-unit remainder.

### Recommendation

Add a validation in `init_transfer_internal` (or at the end of `init_transfer`) that computes `normalize_amount(amount_without_fee())` for the destination chain and requires it to be > 0 before locking tokens and storing the transfer message. If the check fails, return the tokens to the sender immediately (return a non-zero value from `ft_on_transfer` to trigger the NEP-141 refund).

Alternatively, implement a `cancel_transfer` function callable by the original sender that removes the pending transfer message and refunds the locked tokens, which would also mitigate this and other stuck-transfer scenarios.

### Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (6-decimal gap, divisor = 1,000,000).
2. Call `ft_transfer_call` with `amount = 500_000` and `fee = 0`, recipient on Ethereum.
3. `init_transfer` passes the `fee < amount` check (0 < 500,000 ✓) and locks 500,000 units.
4. Relayer calls `sign_transfer` → `normalize_amount(500_000, {24, 18})` = 500_000 / 1_000_000 = 0 → panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`.
5. No cancel path exists. Tokens remain locked in the bridge contract permanently. [4](#0-3) [1](#0-0)

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

**File:** near/omni-bridge/src/lib.rs (L1094-1094)
```rust
        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);
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

**File:** near/omni-types/src/lib.rs (L593-595)
```rust
    pub fn amount_without_fee(&self) -> Option<u128> {
        self.amount.0.checked_sub(self.fee.fee.0)
    }
```
