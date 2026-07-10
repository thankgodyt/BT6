### Title
Unsigned Integer Subtraction Underflow in PSBT Gas Fee Computation Causes Panic and Temporary Fund Lock - (File: contracts/satoshi-bridge/src/psbt.rs)

### Summary
In `psbt.rs`, two unsigned integer subtractions computing `gas_fee` from PSBT input/output amounts are performed **before** any bounds validation. With Rust's `overflow-checks = true` (enforced in `Cargo.toml`), a subtraction that would go negative causes a runtime panic. A relayer who submits a crafted PSBT where total output value exceeds total input value triggers this panic, causing the `sign_btc_transaction` call to revert while the user's nBTC remains locked in the bridge's pending state.

### Finding Description
In `check_psbt_output_all_change_address` (line 151) and `check_withdraw_psbt` (line 238), the gas fee is computed as a plain unsigned subtraction:

```rust
// psbt.rs line 151 (check_psbt_output_all_change_address)
let gas_fee = input_amount - output_amount;

// psbt.rs line 238 (check_withdraw_psbt)
let gas_fee = total_input_amount - total_output_amount;
```

The bounds check on `gas_fee` (e.g., `gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee`) only appears **after** these subtractions at lines 153–159 and 252–258 respectively. If a relayer submits a PSBT where the sum of outputs exceeds the sum of inputs, the subtraction panics before any validation can occur.

Additionally, in `check_withdraw_psbt` lines 242–243, two further unguarded subtractions follow:

```rust
let max_received_amount = amount - withdraw_fee - gas_fee;
let min_received_amount = max_received_amount - config.min_change_amount;
```

If `gas_fee` is large (e.g., relayer sets PSBT outputs near zero so `gas_fee ≈ total_input_amount`), `amount - withdraw_fee - gas_fee` also underflows and panics before the gas fee range check at line 252.

This is the direct analog of the `variance()` Solidity bug: an unsigned subtraction is performed before the guard that would have caught the invalid value.

### Impact Explanation
When `sign_btc_transaction` panics, the NEAR transaction reverts. The `BTCPendingInfo` created during `ft_on_transfer` (where the user's nBTC was already transferred to the bridge) persists in `PendingSign` stage. The user's nBTC is locked in the bridge until a legitimate relayer successfully completes the signing flow or an operator intervenes. This constitutes attacker-triggered temporary locking of bridged funds — **Medium** impact.

### Likelihood Explanation
The relayer role is a public bridge participant (any NEAR account can act as a relayer to submit PSBTs). A malicious relayer targeting a specific user's withdrawal can craft a PSBT with `total_output_amount > total_input_amount` or with near-zero outputs, reliably triggering the panic on every signing attempt for that pending withdrawal. The attack is cheap and repeatable.

### Recommendation
Replace the bare subtractions with checked arithmetic and validate ordering before computing:

```rust
// In check_psbt_output_all_change_address
let gas_fee = input_amount.checked_sub(output_amount)
    .unwrap_or_else(|| env::panic_str("Output amount exceeds input amount"));

// In check_withdraw_psbt
let gas_fee = total_input_amount.checked_sub(total_output_amount)
    .unwrap_or_else(|| env::panic_str("Total output exceeds total input"));

let max_received_amount = amount.checked_sub(withdraw_fee)
    .and_then(|v| v.checked_sub(gas_fee))
    .unwrap_or_else(|| env::panic_str("Fees exceed withdrawal amount"));

let min_received_amount = max_received_amount.checked_sub(config.min_change_amount)
    .unwrap_or_else(|| env::panic_str("max_received_amount below min_change_amount"));
```

Alternatively, add explicit `require!` guards before each subtraction to produce a clear error message rather than a panic.

### Proof of Concept
1. User calls `ft_on_transfer` transferring 100,000 sat worth of nBTC to the bridge, creating a `BTCPendingInfo` in `PendingSign` stage.
2. Malicious relayer calls `sign_btc_transaction` with a PSBT where:
   - Inputs: bridge UTXOs totaling 100,000 sat (`total_input_amount = 100_000`)
   - Outputs: a single output of 200,000 sat (`total_output_amount = 200_000`)
3. Execution reaches `psbt.rs` line 238: `let gas_fee = 100_000u128 - 200_000u128;`
4. With `overflow-checks = true`, Rust panics: "attempt to subtract with overflow".
5. The NEAR transaction reverts; `BTCPendingInfo` remains in `PendingSign` stage with the user's nBTC locked.
6. The malicious relayer repeats this on every signing attempt, indefinitely blocking the withdrawal. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** contracts/satoshi-bridge/src/psbt.rs (L148-161)
```rust
                u128::from(v.value.to_sat())
            })
            .sum::<u128>();
        let gas_fee = input_amount - output_amount;
        if !is_cancel {
            require!(
                gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
                format!(
                    "Invalid gas fee ({}). valid range: [{}, {}].",
                    gas_fee, config.min_btc_gas_fee, config.max_btc_gas_fee
                )
            );
        }
        (output_amount, gas_fee)
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L236-244)
```rust
            );
        }
        let gas_fee = total_input_amount - total_output_amount;
        // When constructing the withdraw transaction, if the change is less than min_change_amount (dust),
        // the caller may deduct a portion from the user's output to make the change amount meet min_change_amount.
        // Therefore, the contract relaxes the validation.
        let max_received_amount = amount - withdraw_fee - gas_fee;
        let min_received_amount = max_received_amount - config.min_change_amount;
        require!(
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L249-258)
```rust
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
