### Title
Excess nBTC Permanently Locked in Bridge Due to Accounting Gap When `actual_received_amount < max_received_amount` - (File: contracts/satoshi-bridge/src/nbtc/burn.rs)

### Summary
When a user withdraws nBTC and the PSBT's `actual_received_amount` is set below `max_received_amount` — a range explicitly permitted by the contract to accommodate dust-threshold change outputs — the difference is permanently locked in the bridge's nBTC balance without being credited to `cur_available_protocol_fee` or returned to the user.

### Finding Description
In `check_withdraw_psbt`, the validation deliberately allows `actual_received_amount` to fall in the range `[min_received_amount, max_received_amount]`, where `min_received_amount = max_received_amount - config.min_change_amount`:

```rust
let max_received_amount = amount - withdraw_fee - gas_fee;
let min_received_amount = max_received_amount - config.min_change_amount;
require!(
    actual_received_amount >= min_received_amount
        && actual_received_amount <= max_received_amount,
    ...
);
``` [1](#0-0) 

The comment explains the intent: the relayer may deduct from the user's output to make the change output meet `min_change_amount`.

In `create_btc_pending_info`, `burn_amount` is set as:
```rust
burn_amount: actual_received_amount + gas_fee,
```

### Citations

**File:** contracts/satoshi-bridge/src/psbt.rs (L242-251)
```rust
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
```
