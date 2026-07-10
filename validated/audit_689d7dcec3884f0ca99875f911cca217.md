### Title
Unchecked Arithmetic Underflow in Withdrawal Amount Computation Causes Panic-Driven Stuck State - (File: contracts/satoshi-bridge/src/psbt.rs)

### Summary

The `check_withdraw_psbt` function performs a chain of unchecked `u128` subtractions to compute the valid received-amount range for a withdrawal. When `withdraw_fee + gas_fee >= amount`, or when the resulting `max_received_amount < config.min_change_amount`, the arithmetic underflows and panics. The root cause is that `get_fee` in `config.rs` can return `fee_min` — a value that is not bounded relative to the withdrawal amount — and no guard prevents the downstream subtraction from underflowing.

This is directly analogous to the dForce `utilizationRate` bug: just as `borrows + cash - reserves` can underflow when `reserves > cash` (producing a nonsensical result or panic), `amount - withdraw_fee - gas_fee` can underflow when fees exceed the withdrawal amount, and `max_received_amount - config.min_change_amount` can underflow when the residual is smaller than the dust threshold.

---

### Finding Description

**Root cause 1 — `get_fee` is not bounded by `amount`:** [1](#0-0) 

`get_fee` returns `max(amount * fee_rate / MAX_RATIO, fee_min)`. Because `fee_rate < MAX_RATIO` is enforced, the first term is always `< amount`. However, `fee_min` is an arbitrary `u128` with no upper-bound validation relative to `min_withdraw_amount`. When `fee_min > amount`, `get_fee` returns a value exceeding the withdrawal amount.

**Root cause 2 — Config validation does not enforce `fee_min < min_withdraw_amount`:** [2](#0-1) 

`assert_valid` only checks `fee_rate < MAX_RATIO` and `protocol_fee_rate <= MAX_RATIO`. There is no check that `deposit_bridge_fee.fee_min < min_deposit_amount` or `withdraw_bridge_fee.fee_min < min_withdraw_amount - max_btc_gas_fee`.

**Root cause 3 — Unchecked subtractions in `check_withdraw_psbt`:** [3](#0-2) 

Three sequential unchecked `u128` subtractions:
1. `gas_fee = total_input_amount - total_output_amount` — underflows if outputs exceed inputs (relayer-constructed PSBT).
2. `max_received_amount = amount - withdraw_fee - gas_fee` — underflows when `withdraw_fee + gas_fee >= amount`.
3. `min_received_amount = max_received_amount - config.min_change_amount` — underflows when `max_received_amount < min_change_amount`.

None of these use `checked_sub`. In a NEAR Wasm build with `overflow-checks = true` (the standard NEAR toolchain default), each underflow is a hard panic that aborts the transaction.

---

### Impact Explanation

**Withdrawal path:** When the panic fires inside `check_withdraw_psbt`, the entire withdrawal callback aborts. The user's nBTC was already transferred to the bridge via `ft_transfer_call`; whether it is returned depends on the NEP-141 callback rollback path. If the rollback itself is not reached (panic before the callback completes), the nBTC can be permanently locked in the bridge contract — a stuck bridge state requiring operator intervention.

**Deposit path (secondary):** The same `get_fee` is used for `deposit_bridge_fee`. If `fee_min > deposit_amount`, the deposit processing panics after the user's BTC has already been sent to the bridge address on-chain. The BTC is stuck with no nBTC minted, requiring a manual refund flow.

---

### Likelihood Explanation

The condition is reachable without any privileged key compromise:

1. An operator (DAO) sets `fee_min` to a value larger than `min_withdraw_amount` — the config validation does not prevent this.
2. Any unprivileged user then submits a withdrawal for an amount between `min_withdraw_amount` and `fee_min`, triggering the underflow on every such withdrawal.
3. Alternatively, even with a correctly configured `fee_min`, a relayer can submit a PSBT where `withdraw_fee + gas_fee` is close to `amount` and `max_received_amount < min_change_amount`, triggering the third underflow.

---

### Recommendation

1. Add a `checked_sub` (or explicit guard) for every subtraction in `check_withdraw_psbt`:
   ```rust
   let max_received_amount = amount
       .checked_sub(withdraw_fee)
       .and_then(|v| v.checked_sub(gas_fee))
       .expect("withdraw_fee + gas_fee exceeds withdrawal amount");
   let min_received_amount = max_received_amount
       .checked_sub(config.min_change_amount)
       .unwrap_or(0);
   ```
2. Add invariant checks in `Config::assert_valid`:
   ```rust
   require!(
       self.withdraw_bridge_fee.fee_min + self.max_btc_gas_fee < self.min_withdraw_amount,
       "fee_min + max_btc_gas_fee must be less than min_withdraw_amount"
   );
   ```
3. Apply the same fix to the deposit fee path.

---

### Proof of Concept

**Setup:**
- `min_withdraw_amount = 10_000` satoshi
- `withdraw_bridge_fee.fee_min = 8_000` satoshi (passes `assert_valid` — only `fee_rate` is checked)
- `min_btc_gas_fee = 3_000` satoshi

**Trigger:**
1. User calls `ft_transfer_call(bridge, amount=10_000, msg=withdraw_msg)`.
2. Bridge computes `withdraw_fee = get_fee(10_000) = max(10_000 * fee_rate / 10_000, 8_000) = 8_000`.
3. Relayer submits a PSBT with `gas_fee = 3_000` (within `[min_btc_gas_fee, max_btc_gas_fee]`).
4. `check_withdraw_psbt` computes `max_received_amount = 10_000 - 8_000 - 3_000 = u128::MAX - 999` (underflow → panic with overflow checks).
5. Transaction aborts; user's nBTC may be stuck depending on callback rollback behavior. [1](#0-0) [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/config.rs (L22-28)
```rust
    pub fn assert_valid(&self) {
        require!(self.fee_rate < MAX_RATIO, "Invalid fee_rate");
        require!(
            self.protocol_fee_rate <= MAX_RATIO,
            "Invalid protocol_fee_rate"
        );
    }
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

**File:** contracts/satoshi-bridge/src/psbt.rs (L238-243)
```rust
        let gas_fee = total_input_amount - total_output_amount;
        // When constructing the withdraw transaction, if the change is less than min_change_amount (dust),
        // the caller may deduct a portion from the user's output to make the change amount meet min_change_amount.
        // Therefore, the contract relaxes the validation.
        let max_received_amount = amount - withdraw_fee - gas_fee;
        let min_received_amount = max_received_amount - config.min_change_amount;
```
