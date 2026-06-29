### Title
`sign_transfer` Minimum Amount Check Applied to Post-Normalization Value While `init_transfer` Lacks the Same Guard, Causing Permanent Token Freezing - (File: `near/omni-bridge/src/lib.rs`)

### Summary
`sign_transfer` validates the outbound amount only after applying `normalize_amount` (floor division by the decimal-difference factor). `init_transfer` only checks `fee < amount`, not that `normalize_amount(amount - fee) > 0`. A user can therefore lock tokens in `init_transfer` that can never be forwarded, because `sign_transfer` will always reject them with `InvalidAmountToTransfer`. There is no cancel or refund path for the stuck `TransferMessage`.

### Finding Description
`sign_transfer` computes the amount that will actually be sent to the destination chain by first subtracting the fee and then normalising:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message
        .amount_without_fee()          // amount - fee
        .near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

`normalize_amount` performs floor division by `10^(origin_decimals − decimals)`:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

For any token whose NEAR representation has more decimals than the destination chain (e.g. `origin_decimals = 24`, `decimals = 18`, factor = 10⁶), any `amount - fee` that is positive but smaller than 10⁶ normalises to **zero**, and `sign_transfer` panics.

`init_transfer`, however, only enforces:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

It does **not** check that `normalize_amount(amount - fee) > 0`. Tokens are locked (or burned for bridge tokens) before this guard is ever reached. Once locked, the `TransferMessage` sits in storage permanently: `remove_transfer_message` is only called from `claim_fee_callback` (requires a valid on-chain `FinTransfer` proof) and `submit_transfer_to_utxo_chain_connector` (BTC/Zcash path). Neither path is reachable for a transfer that was never signed.

The `update_transfer_fee` function cannot help: it only allows the fee to be **increased** (`fee.fee >= current_fee.fee`), so the user cannot reduce the fee to make `amount - fee` larger.

### Impact Explanation
Any user who initiates a NEAR → EVM (or other destination) transfer with `amount - fee < 10^(origin_decimals − decimals)` will have their tokens permanently locked in the bridge contract with no recovery path. This constitutes permanent freezing of bridged funds.

### Likelihood Explanation
The condition is reachable for any token registered with a decimal difference between NEAR and the destination chain. For a 6-decimal gap (e.g. a 24-decimal NEAR token bridged to an 18-decimal EVM token), any transfer of fewer than 1,000,000 base units after fee deduction triggers the freeze. Users transferring small amounts or tokens with large decimal gaps are directly at risk. No privileged access is required; the standard `ft_transfer_call` entry point is sufficient.

### Recommendation
Add the normalization guard inside `init_transfer` (or `init_transfer_internal`) before tokens are locked:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

Alternatively, add a user-facing cancel/refund function that removes the `TransferMessage` and returns the locked tokens when no signature has been produced.

### Proof of Concept
1. Token is registered with `origin_decimals = 24`, `decimals = 18` (normalization factor = 10⁶).
2. User calls `ft_transfer_call` with `amount = 500_000`, `fee = 0`.
3. `init_transfer` passes the only guard (`fee < amount` → `0 < 500_000` ✓); tokens are locked.
4. Relayer calls `sign_transfer`.
5. `normalize_amount(500_000 - 0) = 500_000 / 1_000_000 = 0` (floor division).
6. `require!(0 > 0, ...)` panics with `InvalidAmountToTransfer`.
7. The `TransferMessage` remains in storage; the 500,000 tokens are permanently frozen. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** near/omni-types/src/lib.rs (L593-595)
```rust
    pub fn amount_without_fee(&self) -> Option<u128> {
        self.amount.0.checked_sub(self.fee.fee.0)
    }
```
