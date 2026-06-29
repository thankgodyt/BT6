### Title
`normalize_amount` Floor Division Causes `sign_transfer` to Always Panic for Small-Amount Transfers, Permanently Locking User Funds — (`near/omni-bridge/src/lib.rs`)

### Summary

The `sign_transfer` function in the NEAR omni-bridge contract applies `normalize_amount` (floor division) to the transfer amount before checking that the result is greater than zero. Because `init_transfer` does not validate that the normalized amount is non-zero at deposit time, a user can lock tokens in the bridge with an amount that always normalizes to zero, making `sign_transfer` permanently panic and the funds irrecoverable.

### Finding Description

`normalize_amount` divides the raw amount by `10^(origin_decimals - decimals)` using integer (floor) division: [1](#0-0) 

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

`sign_transfer` calls this function and then requires the result to be strictly positive: [2](#0-1) 

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
```

However, `init_transfer` (the deposit entry point) only checks that `fee < amount`; it does **not** verify that `normalize_amount(amount - fee) > 0`: [3](#0-2) 

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
```

For any token where `origin_decimals > decimals` (e.g., 24 on Ethereum, 18 on NEAR — `diff_decimals = 6`), any transfer amount smaller than `10^diff_decimals` (i.e., less than 1,000,000 in the smallest unit) normalizes to zero. Once such a transfer is stored, every subsequent call to `sign_transfer` for that `transfer_id` will unconditionally panic with `ERR_INVALID_AMOUNT_TO_TRANSFER`. There is no `cancel_transfer` or refund path; `remove_transfer_message` is only reachable through `claim_fee_callback`, which itself requires a proof of destination-chain finalization — impossible without a successful `sign_transfer`.

### Impact Explanation

User tokens deposited via `ft_transfer_call` → `ft_on_transfer` → `init_transfer` are immediately locked in the bridge contract. If the deposited amount (minus fee) is below the normalization threshold, the MPC signing step (`sign_transfer`) can never succeed, and the tokens are permanently frozen with no recovery mechanism. This satisfies the critical impact criterion of **permanent freezing of bridged funds**.

### Likelihood Explanation

The condition is triggered whenever:
1. A token is registered with `origin_decimals > decimals` (a standard configuration for bridging high-precision tokens to NEAR), and
2. A user transfers an amount smaller than `10^(origin_decimals - decimals)` in the token's smallest unit.

Both conditions are realistic in normal bridge usage (e.g., a user sending a dust amount, or a UI rounding error). An attacker can also deliberately trigger this to grief specific users by front-running or social engineering, though the primary risk is accidental.

### Recommendation

Add a normalization check inside `init_transfer` (or `init_transfer_internal`) before accepting the deposit:

```rust
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

Alternatively, enforce a minimum deposit amount equal to `10^(origin_decimals - decimals)` at the `ft_on_transfer` entry point so that the transfer is rejected before tokens are locked.

### Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (`diff_decimals = 6`).
2. Call `ft_transfer_call` with `amount = 500_000` (< 10^6) and `fee = 0`. `init_transfer` accepts it: `0 < 500_000` passes.
3. Tokens are now locked in the bridge.
4. Call `sign_transfer` for the stored `transfer_id`.
5. `normalize_amount(500_000, {24, 18}) = 500_000 / 1_000_000 = 0` (floor division).
6. `require!(0 > 0, ...)` panics — `sign_transfer` always fails.
7. No `cancel_transfer` exists; `claim_fee_callback` requires destination-chain proof that can never be generated. Funds are permanently locked. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
