### Title
Unchecked Arithmetic Underflow in `check_withdraw_psbt` Causes Panic-Driven Transaction Failure - (File: contracts/satoshi-bridge/src/psbt.rs)

---

### Summary

The `check_withdraw_psbt` function performs sequential unchecked arithmetic subtractions on values that are partially user-controlled, without prior bounds validation. A user initiating a withdrawal can craft a PSBT where the computed `gas_fee` exceeds `amount - withdraw_fee`, triggering an arithmetic underflow panic before any range guard is reached.

---

### Finding Description

In `check_withdraw_psbt`, three sequential plain subtractions are performed on `u128` values:

```rust
// psbt.rs line 238
let gas_fee = total_input_amount - total_output_amount;

// psbt.rs line 242-243
let max_received_amount = amount - withdraw_fee - gas_fee;
let min_received_amount = max_received_amount - config.min_change_amount;
```

The critical gas-fee range guard appears only at lines 252–258, **after** the subtractions at lines 242–243:

```rust
require!(
    gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
    ...
);
```

The ordering means that even when `gas_fee` is within the configured valid range, if `gas_fee > amount - withdraw_fee`, the subtraction at line 242 underflows and panics before the range check is ever evaluated.

**User-controlled inputs:**
- `amount`: the nBTC amount the user burns (must be ≥ `min_withdraw_amount`, but can be small)
- PSBT outputs: the user specifies the output set, which determines `total_output_amount` and therefore `gas_fee = total_input_amount - total_output_amount`

There is no pre-check that `amount >= withdraw_fee + gas_fee` before line 242, and no pre-check that `max_received_amount >= config.min_change_amount` before line 243.

Additionally, line 238 itself can underflow if the user submits PSBT outputs whose sum exceeds the selected UTXO inputs — the contract performs no prior guard that `total_output_amount <= total_input_amount`. [1](#0-0) [2](#0-1) 

---

### Impact Explanation

With NEAR SDK's default `overflow-checks = true` in release builds, each underflow is a hard panic that reverts the entire NEAR transaction. Because the panic occurs inside `ft_on_transfer` (invoked by `ft_transfer_call`), the NEP-141 standard requires the nBTC tokens to be returned to the sender — so user funds are not permanently lost. The concrete harm is:

- The user's withdrawal is silently aborted with a cryptic panic rather than a descriptive error.
- The user loses NEAR gas for the failed transaction.
- No diagnostic information is surfaced to help the user understand why the withdrawal failed or how to fix it — an exact analog to the 0x report's complaint that "there is no easy way to know exactly which computation caused it."

This matches the **Low** allowed impact: *publicly reachable panic-driven fault in production bridge/token paths without direct theft.* [3](#0-2) 

---

### Likelihood Explanation

Any unprivileged NEAR account holding nBTC can trigger this. The withdrawal PSBT (inputs + outputs) is constructed and submitted entirely by the user via `ft_transfer_call` → `TokenReceiverMessage::Withdraw`. No special role or operator cooperation is required. The triggering condition — `gas_fee > amount - withdraw_fee` — is reachable whenever a user burns a small `amount` while the configured `max_btc_gas_fee` is larger than `min_withdraw_amount - min_bridge_fee`, a common configuration. [4](#0-3) 

---

### Recommendation

Replace the three bare subtractions with checked arithmetic and surface a clear error message before any range guard:

```rust
// Line 238
let gas_fee = total_input_amount
    .checked_sub(total_output_amount)
    .unwrap_or_else(|| env::panic_str("Output amount exceeds input amount"));

// Line 242
let max_received_amount = amount
    .checked_sub(withdraw_fee)
    .and_then(|v| v.checked_sub(gas_fee))
    .unwrap_or_else(|| env::panic_str("gas_fee + withdraw_fee exceeds withdrawal amount"));

// Line 243
let min_received_amount = max_received_amount
    .checked_sub(config.min_change_amount)
    .unwrap_or_else(|| env::panic_str("max_received_amount less than min_change_amount"));
```

Move the `gas_fee` range check to immediately after line 238 so that out-of-range gas fees are rejected with a clear message before any dependent arithmetic is attempted.

---

### Proof of Concept

1. Bridge has a UTXO worth 500 000 satoshis. `max_btc_gas_fee = 50 000`, `min_withdraw_amount = 10 000`, bridge fee rate produces `withdraw_fee = 1 000` for a 10 000-satoshi withdrawal.
2. User calls `ft_transfer_call` burning `amount = 10 000` nBTC with a `TokenReceiverMessage::Withdraw` PSBT that:
   - Selects the 500 000-satoshi UTXO as input.
   - Specifies a single output of 450 000 satoshis to the change address (no user-output, or a tiny user-output).
   - Resulting `gas_fee = 500 000 − 450 000 = 50 000` (within the valid range `[min_btc_gas_fee, max_btc_gas_fee]`).
3. Execution reaches line 242: `max_received_amount = 10 000 − 1 000 − 50 000` → underflow → panic.
4. The NEAR transaction reverts. The user's 10 000 nBTC are returned by the NEP-141 callback, but the user receives no actionable error message and loses NEAR gas. [5](#0-4) [6](#0-5)

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

**File:** contracts/satoshi-bridge/src/config.rs (L30-35)
```rust
    pub fn get_fee(&self, amount: u128) -> u128 {
        std::cmp::max(
            amount * u128::from(self.fee_rate) / u128::from(MAX_RATIO),
            self.fee_min,
        )
    }
```

**File:** contracts/satoshi-bridge/src/config.rs (L83-87)
```rust
    #[serde(with = "u128_dec_format")]
    pub min_btc_gas_fee: u128,
    // The max gas fee applicable for Bitcoin transactions
    #[serde(with = "u128_dec_format")]
    pub max_btc_gas_fee: u128,
```
