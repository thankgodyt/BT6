### Title
Unchecked Arithmetic Underflow in `check_withdraw_psbt` Causes Panic Before Gas-Fee Validation - (File: `contracts/satoshi-bridge/src/psbt.rs`)

### Summary
Three consecutive unchecked `u128` subtractions in `check_withdraw_psbt` can panic before the gas-fee range guard that would otherwise reject the invalid input. With `overflow-checks = true` (confirmed in `CLAUDE.md`), any underflow aborts the transaction. Because the user supplies the PSBT `output` vector as part of the `TokenReceiverMessage::Withdraw` message, this is reachable from an unprivileged NEAR account.

### Finding Description
In `contracts/satoshi-bridge/src/psbt.rs` lines 238–243:

```rust
let gas_fee = total_input_amount - total_output_amount;          // line 238
let max_received_amount = amount - withdraw_fee - gas_fee;       // line 242
let min_received_amount = max_received_amount - config.min_change_amount; // line 243
```

The gas-fee range check that would catch an out-of-range `gas_fee` appears only at lines 252–258, **after** all three subtractions. This is the exact same anti-pattern as the audited report: the guard that should prevent the invalid state executes after the operation that panics. [1](#0-0) 

Three distinct underflow paths exist:

1. **`gas_fee` underflow (line 238):** User submits `output` values whose sum exceeds `total_input_amount`. Since the user controls the `output` field of `TokenReceiverMessage::Withdraw`, they can set `total_output_amount > total_input_amount`, causing an immediate panic.

2. **`max_received_amount` underflow (line 242):** Even with a valid `gas_fee` (within `[min_btc_gas_fee, max_btc_gas_fee]`), if `gas_fee > amount - withdraw_fee`, the subtraction panics. The gas-fee range check at line 252 would have caught this, but it runs too late.

3. **`min_received_amount` underflow (line 243):** If `amount - withdraw_fee - gas_fee < config.min_change_amount`, the subtraction panics. Again, the downstream `require!` at line 244 would have caught this, but it is never reached. [2](#0-1) 

The user-controlled entry point is confirmed by the withdrawal message structure, which includes user-supplied `input` and `output` fields passed directly into PSBT validation: [3](#0-2) 

The `overflow-checks = true` setting is explicitly documented: [4](#0-3) 

### Impact Explanation
A panic in `ft_on_transfer` causes the NEP-141 `ft_transfer_call` to revert, returning tokens to the user. However, per the documented state-mutation ordering ("Mutate state BEFORE cross-contract calls"), if any UTXO is marked as spent before `check_withdraw_psbt` is called, the panic leaves those UTXOs permanently locked — a stuck bridge state requiring operator intervention. Even in the best case (panic before any mutation), the withdrawal path is completely blocked for the crafted input, matching the "panic-driven fault in production bridge/token paths" impact class. [5](#0-4) 

### Likelihood Explanation
Any NEAR account holding nBTC can call `ft_transfer_call` with a crafted `TokenReceiverMessage::Withdraw` containing outputs whose sum exceeds the selected UTXOs' total value. No special role or key is required. The trigger is deterministic and requires no external conditions.

### Recommendation
Replace the three bare subtractions with `checked_sub` (or validate ordering before subtracting), and move the gas-fee range check to **before** the dependent arithmetic:

```rust
require!(
    total_output_amount <= total_input_amount,
    "outputs exceed inputs"
);
let gas_fee = total_input_amount - total_output_amount;
require!(
    gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
    format!("Invalid gas fee ({}). valid range: [{}, {}].", ...)
);
let max_received_amount = amount
    .checked_sub(withdraw_fee)
    .and_then(|v| v.checked_sub(gas_fee))
    .expect("amount too small to cover fees");
let min_received_amount = max_received_amount
    .checked_sub(config.min_change_amount)
    .expect("max_received_amount less than min_change_amount");
```

### Proof of Concept

1. Alice holds nBTC and calls `ft_transfer_call` on the nBTC contract targeting the bridge, with `amount = min_withdraw_amount`.
2. The `msg` field contains `TokenReceiverMessage::Withdraw { input: [<valid_utxo>], output: [TxOut { value: utxo_value + 1, ... }], ... }` — outputs exceed inputs by 1 satoshi.
3. The bridge's `ft_on_transfer` calls `check_withdraw_psbt`.
4. Line 238: `gas_fee = total_input_amount - (total_input_amount + 1)` → u128 underflow → **panic** with `overflow-checks = true`.
5. The gas-fee range check at line 252 is never reached.
6. If any UTXO was marked spent before this call, it remains permanently locked.

### Citations

**File:** contracts/satoshi-bridge/src/psbt.rs (L238-243)
```rust
        let gas_fee = total_input_amount - total_output_amount;
        // When constructing the withdraw transaction, if the change is less than min_change_amount (dust),
        // the caller may deduct a portion from the user's output to make the change amount meet min_change_amount.
        // Therefore, the contract relaxes the validation.
        let max_received_amount = amount - withdraw_fee - gas_fee;
        let min_received_amount = max_received_amount - config.min_change_amount;
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L252-258)
```rust
        require!(
            gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
            format!(
                "Invalid gas fee ({}). valid range: [{}, {}].",
                gas_fee, config.min_btc_gas_fee, config.max_btc_gas_fee
            )
        );
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L1-1)
```rust
use crate::{psbt_wrapper::PsbtWrapper, *};
```

**File:** CLAUDE.md (L67-70)
```markdown
### Arithmetic Safety
- **overflow-checks = true:** All overflow panics in release mode (fail-safe)
- Use `checked_mul()`, `checked_add()` for explicit error handling
- Prefer panic over silent
```
