### Title
Arithmetic Underflow in `check_withdraw_psbt` Causes Unexpected Panic-Driven Revert in Withdrawal Path - (File: contracts/satoshi-bridge/src/psbt.rs)

### Summary
In `check_withdraw_psbt`, the computation of `min_received_amount` performs an unchecked subtraction of `config.min_change_amount` from `max_received_amount`. When `max_received_amount < config.min_change_amount` — a reachable condition when gas fees are high relative to the withdrawal amount — this subtraction underflows, causing an unexpected panic or wrap-around before any meaningful validation error is returned. The gas-fee range check that would otherwise catch the problematic input appears only *after* the underflow site.

### Finding Description

In `contracts/satoshi-bridge/src/psbt.rs`, `check_withdraw_psbt` computes the valid range for the user's output amount as follows:

```rust
let max_received_amount = amount - withdraw_fee - gas_fee;
let min_received_amount = max_received_amount - config.min_change_amount;  // ← underflow site
require!(
    actual_received_amount >= min_received_amount
        && actual_received_amount <= max_received_amount,
    ...
);
require!(
    gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
    ...
);
``` [1](#0-0) 

The comment immediately above the underflow site acknowledges the intent: `min_received_amount` is deliberately set below `max_received_amount` to allow the relayer to absorb dust into the user output. However, no guard is placed on the case where `max_received_amount` itself is smaller than `config.min_change_amount`.

The gas-fee bounds check (`gas_fee >= min_btc_gas_fee && gas_fee <= max_btc_gas_fee`) is evaluated *after* the subtraction, so it cannot prevent the underflow. With Rust's default overflow checks enabled (common in NEAR contract builds), the subtraction panics. Without them, it wraps to a near-`u128::MAX` value, causing the subsequent `require!` to fire with a confusing, misleading error message rather than a clear "gas fee too high" diagnostic.

The entry path is fully public: any NEAR account can call `ft_transfer_call` on the nBTC contract with a `Withdraw` message, supplying a PSBT whose `total_input_amount - total_output_amount` (i.e., `gas_fee`) is large enough to push `max_received_amount` below `config.min_change_amount`. [2](#0-1) 

### Impact Explanation

When the underflow is triggered, `ft_on_transfer` panics (or emits a misleading require-failure). Under NEAR's NEP-141 `ft_transfer_call` protocol, a failed `ft_on_transfer` causes `ft_resolve_transfer` to refund the tokens to the sender, so no nBTC is permanently lost. The impact is therefore a publicly reachable panic-driven fault in the production withdrawal path: the user's transaction fails with an opaque error instead of a clear validation message, and the bridge's withdrawal state machine is not advanced. This matches the allowed Low impact: *"Publicly reachable invariant-violation, stuck-state, or panic-driven fault in production bridge/token paths without direct theft."*

### Likelihood Explanation

Any unprivileged user who constructs a withdrawal PSBT with a gas fee high enough that `amount - withdraw_fee - gas_fee < config.min_change_amount` will trigger this path. This is reachable with a small withdrawal amount (near `min_withdraw_amount`) combined with a gas fee near `max_btc_gas_fee`. No special role or leaked key is required; the only prerequisite is holding nBTC tokens.

### Recommendation

Guard the subtraction before it is performed:

```rust
let max_received_amount = amount - withdraw_fee - gas_fee;
let min_received_amount = max_received_amount.saturating_sub(config.min_change_amount);
```

Or, equivalently, move the gas-fee bounds check *before* the `min_received_amount` computation so that an out-of-range gas fee is rejected with a clear error before any arithmetic on `max_received_amount` is attempted.

### Proof of Concept

1. Alice holds nBTC and calls `ft_transfer_call` on the nBTC contract targeting the bridge, with:
   - `amount = 10_000` sats (just above `min_withdraw_amount`)
   - A PSBT whose `total_input_amount - total_output_amount = 9_500` (gas fee within `max_btc_gas_fee`)
   - `withdraw_fee ≈ 100` sats → `max_received_amount = 400`
   - `config.min_change_amount = 1_000` (typical dust limit)
2. `ft_on_transfer` → `ft_on_transfer_withdraw_chain_specific` → `create_btc_pending_info` → `check_withdraw_psbt_valid` → `check_withdraw_psbt`.
3. At line 243 of `psbt.rs`, `400u128 - 1_000u128` underflows → panic (with overflow checks) or wraps to `u128::MAX - 599` (without), causing the subsequent `require!` to fire with a misleading range error.
4. `ft_on_transfer` reverts; `ft_resolve_transfer` refunds Alice's nBTC. The withdrawal is silently aborted with no actionable error. [3](#0-2)

### Citations

**File:** contracts/satoshi-bridge/src/psbt.rs (L238-258)
```rust
        let gas_fee = total_input_amount - total_output_amount;
        // When constructing the withdraw transaction, if the change is less than min_change_amount (dust),
        // the caller may deduct a portion from the user's output to make the change amount meet min_change_amount.
        // Therefore, the contract relaxes the validation.
        let max_received_amount = amount - withdraw_fee - gas_fee;
        let min_received_amount = max_received_amount - config.min_change_amount;
        require!(
            actual_received_amount >= min_received_amount
                && actual_received_amount <= max_received_amount,
            format!(
                "The user's output amount ({}) is out of the valid range ({}, {})",
                actual_received_amount, min_received_amount, max_received_amount
            )
        );
        require!(
            gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
            format!(
                "Invalid gas fee ({}). valid range: [{}, {}].",
                gas_fee, config.min_btc_gas_fee, config.max_btc_gas_fee
            )
        );
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L51-65)
```rust
            TokenReceiverMessage::Withdraw {
                target_btc_address,
                input,
                output,
                max_gas_fee,
                chain_specific_data,
            } => self.ft_on_transfer_withdraw_chain_specific(
                sender_id,
                amount,
                target_btc_address,
                input,
                output,
                max_gas_fee,
                chain_specific_data,
            ),
```
