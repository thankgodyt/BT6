### Title
Unsigned Integer Underflow in `check_withdraw_psbt` Causes Panic on Legitimate Withdrawal Configurations - (File: contracts/satoshi-bridge/src/psbt.rs)

### Summary
`check_withdraw_psbt` performs unsigned `u128` subtractions at lines 238, 242, and 243 without prior bounds checks. Because the release profile sets `overflow-checks = true`, any underflow aborts the contract (panic). A user-controlled withdrawal where `amount - withdraw_fee - gas_fee < config.min_change_amount` causes line 243 to panic before any clean `require!` guard fires, making that class of withdrawal configurations permanently unreachable.

### Finding Description
In `check_withdraw_psbt`, three sequential unsigned subtractions are performed:

```rust
// line 238
let gas_fee = total_input_amount - total_output_amount;
// line 242
let max_received_amount = amount - withdraw_fee - gas_fee;
// line 243
let min_received_amount = max_received_amount - config.min_change_amount;
```

The gas-fee range check (`gas_fee >= min_btc_gas_fee && gas_fee <= max_btc_gas_fee`) only appears at lines 252–258, **after** all three subtractions. The `min_change_amount` subtraction at line 243 has no guard at all.

`overflow-checks = true` is set in the workspace `[profile.release]`, so any underflow panics (aborts) rather than wrapping. [1](#0-0) [2](#0-1) 

The comment at lines 239–241 explicitly documents the intent of line 243: the contract is supposed to allow the relayer to deduct up to `min_change_amount` from the user's output to avoid dust change. But when `max_received_amount < config.min_change_amount` (i.e., the user's net amount after fees is smaller than the dust threshold), the subtraction underflows and the contract panics instead of emitting a clean error. [3](#0-2) 

### Impact Explanation
The panic aborts `ft_on_transfer`, causing `ft_resolve_transfer` in the nBTC contract to return the tokens to the user. No funds are permanently lost. However, the entire class of withdrawals where `amount - withdraw_fee - gas_fee < config.min_change_amount` is unreachable: the contract panics rather than returning a descriptive error, and the user cannot complete the withdrawal at those parameters. This is a panic-driven fault in a production bridge path without direct theft.

### Likelihood Explanation
Any unprivileged nBTC holder can trigger this by calling `ft_transfer_call` with:
- `amount` set to `min_withdraw_amount`
- PSBT outputs chosen so that `total_input_amount - total_output_amount` equals `max_btc_gas_fee`

If `min_withdraw_amount - withdraw_fee(min_withdraw_amount) - max_btc_gas_fee < config.min_change_amount`, the panic fires. Whether this condition holds depends on the deployed config values, but no on-chain invariant prevents it: `assert_valid` does not enforce `min_withdraw_amount - fee_min - max_btc_gas_fee >= min_change_amount`. [4](#0-3) 

### Recommendation
Replace the bare subtractions with `checked_sub` (or equivalent `require!` guards before each subtraction) so that underflow produces a descriptive error rather than a panic:

```rust
let gas_fee = total_input_amount
    .checked_sub(total_output_amount)
    .unwrap_or_else(|| env::panic_str("output exceeds input"));

let max_received_amount = amount
    .checked_sub(withdraw_fee)
    .and_then(|v| v.checked_sub(gas_fee))
    .unwrap_or_else(|| env::panic_str("fees exceed withdrawal amount"));

let min_received_amount = max_received_amount
    .saturating_sub(config.min_change_amount);
```

Using `saturating_sub` for `min_received_amount` is appropriate because the intent (allow up to `min_change_amount` shortfall) is naturally expressed as "floor at zero."

### Proof of Concept

Assume config:
- `min_withdraw_amount = 10_000` sat
- `withdraw_bridge_fee = { fee_min: 1_000, fee_rate: 0 }` → `withdraw_fee = 1_000`
- `max_btc_gas_fee = 9_500`
- `min_change_amount = 546` (Bitcoin dust limit)

User calls `ft_transfer_call` with `amount = 10_000` and a PSBT whose inputs total 20_000 sat and outputs total 10_500 sat (all to the target address), leaving `gas_fee = 9_500`.

Execution in `check_withdraw_psbt`:
1. `gas_fee = 20_000 - 10_500 = 9_500` ✓
2. `max_received_amount = 10_000 - 1_000 - 9_500 = -500` → **u128 underflow → panic**

The panic fires at line 242 before the gas-fee range check at line 252. The transaction aborts; the user's 10_000 nBTC is returned, but the withdrawal cannot be completed at these parameters. [5](#0-4) [6](#0-5)

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

**File:** Cargo.toml (L27-27)
```text
overflow-checks = true
```

**File:** contracts/satoshi-bridge/src/config.rs (L30-35)
```rust
    pub fn get_fee(&self, amount: u128) -> u128 {
        std::cmp::max(
            amount * u128::from(self.fee_rate) / u128::from(MAX_RATIO),
            self.fee_min,
        )
    }
```

**File:** contracts/satoshi-bridge/src/config.rs (L123-158)
```rust
impl Config {
    pub fn assert_valid(&self) {
        let confirmations_valid_range = 2..=100;
        require!(
            self.confirmations_strategy
                .values()
                .all(|v| confirmations_valid_range.contains(v)),
            "Invalid confirmations_strategy"
        );
        self.deposit_bridge_fee.assert_valid();
        self.withdraw_bridge_fee.assert_valid();
        require!(
            self.min_change_amount < self.max_change_amount,
            "min_change_amount must be less than max_change_amount"
        );
        require!(
            self.min_btc_gas_fee < self.max_btc_gas_fee,
            "min_btc_gas_fee must be less than max_btc_gas_fee"
        );
        require!(
            self.active_management_lower_limit < self.active_management_upper_limit,
            "active_management_lower_limit must be less than active_management_upper_limit"
        );
        require!(
            self.passive_management_lower_limit < self.passive_management_upper_limit,
            "passive_management_lower_limit must be less than passive_management_upper_limit"
        );
        require!(
            u128::from(self.unhealthy_utxo_amount) > self.min_change_amount,
            "unhealthy_utxo_amount must be greater than min_change_amount"
        );
        require!(
            self.refund_timelock_sec <= self.unsafe_refund_timelock_sec,
            "refund_timelock_sec must be <= unsafe_refund_timelock_sec"
        );
    }
```
