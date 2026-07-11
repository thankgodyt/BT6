### Title
Unchecked Unsigned-Integer Subtraction in `check_withdraw_psbt` Panics Before Gas-Fee Range Validation - (File: contracts/satoshi-bridge/src/psbt.rs)

### Summary
`check_withdraw_psbt` performs two sequential bare `u128` subtractions at lines 242–243 before the gas-fee range guard at lines 252–258. With `overflow-checks = true` (the project's release profile), either subtraction panics when the minuend is smaller than the subtrahend. Any NEAR account can reach this path via `ft_transfer_call` → `ft_on_transfer` → `create_btc_pending_info` → `check_withdraw_psbt_valid` → `check_withdraw_psbt`.

### Finding Description

In `check_withdraw_psbt`, after computing `gas_fee` from the PSBT:

```rust
// psbt.rs line 238
let gas_fee = total_input_amount - total_output_amount;

// psbt.rs line 242
let max_received_amount = amount - withdraw_fee - gas_fee;

// psbt.rs line 243
let min_received_amount = max_received_amount - config.min_change_amount;
```

The guard that bounds `gas_fee` to `[min_btc_gas_fee, max_btc_gas_fee]` appears only at lines 252–258, **after** both subtractions. There is no prior assertion that:

1. `amount >= withdraw_fee + gas_fee` (guards line 242), or
2. `amount - withdraw_fee - gas_fee >= config.min_change_amount` (guards line 243).

`gas_fee` is derived entirely from the caller-supplied PSBT: `total_input_amount - total_output_amount`. A user who sets `total_output_amount` low (e.g., a single tiny user-output with no change) produces an arbitrarily large `gas_fee`, making line 242 underflow. Even with a gas fee within the valid range, if `amount - withdraw_fee - gas_fee < config.min_change_amount`, line 243 underflows. The config validator (`Config::assert_valid`) enforces no relationship between `min_withdraw_amount`, `fee_min`, `max_btc_gas_fee`, and `min_change_amount`, so this gap is reachable under legitimate configurations.

The call chain is fully public:

```
nbtc.ft_transfer_call(bridge, amount, WithdrawMsg)
  → bridge.ft_on_transfer(sender, amount, msg)          [token_receiver.rs:23]
    → create_btc_pending_info(...)                       [token_receiver.rs:71]
      → check_withdraw_psbt_valid(...)                   [token_receiver.rs:90]
        → check_withdraw_psbt(...)                       [psbt.rs:164]
          → line 242 / 243 panic
```

### Impact Explanation

With `overflow-checks = true`, the panic aborts the entire `ft_on_transfer` receipt. Under NEP-141, a failed `ft_on_transfer` causes `ft_transfer_call` to refund the tokens to the sender, so no nBTC is permanently lost. However, the withdrawal is silently aborted with no useful error message, and any legitimate user whose `amount - withdraw_fee - gas_fee` falls below `min_change_amount` (a configuration-dependent but reachable condition) cannot complete a withdrawal. This constitutes a publicly reachable panic-driven fault in the production bridge withdrawal path.

**Impact: Low** — Publicly reachable panic-driven fault in production bridge path without direct theft.

### Likelihood Explanation

Any NEAR account holding nBTC can trigger the line-242 panic by submitting a withdrawal PSBT with a very small `total_output_amount`. The line-243 panic is reachable by any user withdrawing near the minimum amount when `max_btc_gas_fee` is close to `min_withdraw_amount - fee_min - min_change_amount`. No privileged role is required; the only prerequisite is holding nBTC tokens.

### Recommendation

Add explicit guards before the subtractions, mirroring the pattern already used in `refund_execution_inputs` (`checked_sub` + `expect`):

```rust
// Guard line 242
let max_received_amount = amount
    .checked_sub(withdraw_fee)
    .and_then(|v| v.checked_sub(gas_fee))
    .unwrap_or_else(|| env::panic_str(
        "amount is insufficient to cover withdraw_fee and gas_fee"
    ));

// Guard line 243
let min_received_amount = max_received_amount
    .checked_sub(config.min_change_amount)
    .unwrap_or_else(|| env::panic_str(
        "max_received_amount is less than min_change_amount"
    ));
```

Additionally, add a validation in `Config::assert_valid` that enforces:
```
min_withdraw_amount > fee_min + max_btc_gas_fee + min_change_amount
```
so the configuration itself cannot create a state where legitimate withdrawals always panic.

### Proof of Concept

1. Alice holds 100,000 nBTC satoshis. `min_withdraw_amount = 70,000`, `fee_min = 50,000`, `min_btc_gas_fee = 10,000`, `max_btc_gas_fee = 200,000`, `min_change_amount = 30,000`.
2. Alice calls `nbtc.ft_transfer_call(bridge, 100_000, WithdrawMsg { input: [utxo_500k], output: [TxOut { value: 1_sat, script: user_addr }], ... })`.
3. `total_input_amount = 500,000`, `total_output_amount = 1` → `gas_fee = 499,999` (line 238, no panic).
4. `withdraw_fee = max(100_000 * rate / 10000, 50_000) = 50,000`.
5. Line 242: `100,000 - 50,000 - 499,999` → **u128 underflow → panic**.
6. `ft_on_transfer` fails; NEP-141 refunds Alice's 100,000 nBTC. Withdrawal is aborted with no meaningful error.

For the line-243 variant: use `gas_fee = 15,000` (within valid range). `max_received_amount = 100,000 - 50,000 - 15,000 = 35,000`. Line 243: `35,000 - 30,000 = 5,000` (no panic here with these numbers). Adjust: `min_change_amount = 40,000` → `35,000 - 40,000` → **panic at line 243**, before the gas-fee range check at line 252 ever executes. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L23-67)
```rust
    fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        let amount = amount.into();
        require!(
            amount >= self.internal_config().min_withdraw_amount,
            "Invalid amount"
        );
        let message = serde_json::from_str::<TokenReceiverMessage>(&msg).expect("INVALID MSG");
        let token_id = env::predecessor_account_id();
        require!(
            token_id == self.internal_config().nbtc_account_id,
            "Invalid token_id"
        );
        match message {
            TokenReceiverMessage::DepositProtocolFee => {
                self.data_mut().acc_collected_protocol_fee += amount;
                self.data_mut().cur_available_protocol_fee += amount;
                Event::DepositProtocolFee {
                    account_id: &sender_id,
                    amount: U128(amount),
                }
                .emit();
                PromiseOrValue::Value(U128(0))
            }
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
        }
    }
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L88-98)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L280-284)
```rust
        let refund_amount = refund_request
            .amount
            .checked_sub(refund_request.gas_fee)
            .expect("Deposit amount too small to cover gas fee");
        require!(refund_amount > 0, "Refund amount is zero after gas fee");
```
