### Title
Gas-Fee Range Check Ordered After Arithmetic That Can Underflow, Causing Panic-Driven Fault in Withdrawal Path - (File: contracts/satoshi-bridge/src/psbt.rs)

### Summary
In `check_withdraw_psbt`, the arithmetic `amount - withdraw_fee - gas_fee` is evaluated before the gas-fee range guard runs. A user can craft a PSBT whose outputs are small enough that `gas_fee` exceeds `amount - withdraw_fee`, triggering an integer-underflow panic before the range check ever executes. The analog to the external report is direct: a guard that should block an invalid value is positioned after the computation that depends on that value being valid, so the computation panics instead of the guard firing cleanly.

### Finding Description
`check_withdraw_psbt` in `contracts/satoshi-bridge/src/psbt.rs` computes:

```rust
let gas_fee = total_input_amount - total_output_amount;   // line 238
// ...
let max_received_amount = amount - withdraw_fee - gas_fee; // line 242  ← can underflow
let min_received_amount = max_received_amount - config.min_change_amount; // line 243
```

The gas-fee range guard appears only later:

```rust
require!(
    gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
    ...
);  // lines 252-258
``` [1](#0-0) 

Because Rust compiles with `overflow-checks = true` in release mode (confirmed by `CLAUDE.md`), the subtraction at line 242 panics before the guard at line 252 can reject the oversized fee. [2](#0-1) 

A user controls `total_output_amount` by choosing the PSBT outputs. Setting the user-facing output to a dust value (e.g., 1 satoshi) and omitting change makes `gas_fee ≈ total_input_amount`, which easily exceeds `amount - withdraw_fee` for any minimum-size withdrawal.

Concrete example with default config (`min_withdraw_amount = 70000`, `fee_min = 50000`, `max_btc_gas_fee = 50000`):

| Variable | Value |
|---|---|
| `amount` | 70 000 sat |
| `withdraw_fee` | 50 000 sat |
| UTXO value | 100 000 sat |
| user output | 1 sat |
| `gas_fee` | 99 999 sat |
| `amount - withdraw_fee - gas_fee` | **−79 999** → panic | [3](#0-2) 

The entry point is `ft_on_transfer` → `ft_on_transfer_withdraw_chain_specific` → `create_btc_pending_info` → `check_withdraw_psbt_valid` → `check_withdraw_psbt`. [4](#0-3) 

### Impact Explanation
The panic reverts the entire `ft_on_transfer` call. NEAR's `ft_resolve_transfer` callback sees a failed promise and refunds the user's nBTC. The UTXO removal performed by `generate_vutxos` is also reverted (NEAR transaction atomicity). No funds are permanently lost and no stuck state results. The impact is a publicly reachable panic-driven fault in the production bridge withdrawal path without direct theft — matching the Low tier of the allowed impact scope. [5](#0-4) 

### Likelihood Explanation
Any nBTC holder can trigger this. The user only needs to observe the bridge's public UTXO set, pick a valid UTXO as input, and submit a `Withdraw` message whose output sum is small enough that `gas_fee > amount - withdraw_fee`. No special role or privileged access is required.

### Recommendation
Move the gas-fee range check to execute **before** the arithmetic that depends on it:

```rust
let gas_fee = total_input_amount - total_output_amount;
// Validate gas_fee FIRST, before any subtraction that uses it
require!(
    gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
    format!("Invalid gas fee ({})...", gas_fee, ...)
);
let max_received_amount = amount
    .checked_sub(withdraw_fee)
    .and_then(|v| v.checked_sub(gas_fee))
    .unwrap_or_else(|| env::panic_str("gas_fee exceeds withdrawable amount"));
let min_received_amount = max_received_amount
    .checked_sub(config.min_change_amount)
    .unwrap_or_else(|| env::panic_str("min_change_amount exceeds max_received_amount"));
```

Using `checked_sub` for the remaining arithmetic provides a clear error message instead of an opaque overflow panic.

### Proof of Concept
1. Alice holds 70 000 nBTC.
2. Bridge has a UTXO worth 100 000 sat.
3. Alice calls `nbtc.ft_transfer_call(bridge, 70000, Withdraw { input: [utxo], output: [TxOut { value: 1, script_pubkey: alice_addr }], ... })`.
4. `ft_on_transfer` → `create_btc_pending_info` → `check_withdraw_psbt`:
   - `gas_fee = 100000 - 1 = 99999`
   - `max_received_amount = 70000 -

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

**File:** CLAUDE.md (L67-70)
```markdown
### Arithmetic Safety
- **overflow-checks = true:** All overflow panics in release mode (fail-safe)
- Use `checked_mul()`, `checked_add()` for explicit error handling
- Prefer panic over silent
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L29-33)
```rust
        let amount = amount.into();
        require!(
            amount >= self.internal_config().min_withdraw_amount,
            "Invalid amount"
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

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L70-98)
```rust
impl Contract {
    pub(crate) fn create_btc_pending_info(
        &mut self,
        sender_id: AccountId,
        amount: u128,
        target_btc_address: String,
        mut psbt: PsbtWrapper,
        max_gas_fee: Option<U128>,
    ) {
        let (utxo_storage_keys, vutxos) = self.generate_vutxos(&mut psbt);
        let max_pending = self.get_max_pending_sign_txs(&sender_id);
        let account = self.internal_unwrap_or_create_mut_account(&sender_id);
        require!(
            account.pending_sign_count() < max_pending,
            "Too many pending sign transactions"
        );

        let withdraw_change_address_script_pubkey =
            self.internal_config().get_change_script_pubkey();
        let withdraw_fee = self.internal_config().withdraw_bridge_fee.get_fee(amount);
        let (actual_received_amount, gas_fee) = self.check_withdraw_psbt_valid(
            target_btc_address.clone(),
            &withdraw_change_address_script_pubkey,
            &psbt,
            &vutxos,
            amount,
            withdraw_fee,
            max_gas_fee,
        );
```
