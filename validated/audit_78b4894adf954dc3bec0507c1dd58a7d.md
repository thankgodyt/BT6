### Title
Missing Cross-Validation Between `fee_min` and `min_withdraw_amount` Allows Panic-Driven Stuck State in Withdrawal Path - (File: `contracts/satoshi-bridge/src/config.rs`)

---

### Summary

`BridgeFee.assert_valid()` validates `fee_rate` and `protocol_fee_rate` against `MAX_RATIO` but places **no upper bound on `fee_min`** relative to `min_withdraw_amount` (or `min_deposit_amount`). `Config.assert_valid()` similarly omits cross-validation between these two fields. If the DAO misconfigures `fee_min > min_withdraw_amount`, `get_fee()` returns a value exceeding the withdrawal amount, causing an arithmetic underflow panic in the withdrawal execution path. With `overflow-checks = true` enforced project-wide, this panic bricks the withdrawal flow for all users until the DAO corrects the configuration.

---

### Finding Description

`BridgeFee.assert_valid()` enforces only two constraints:

```rust
// contracts/satoshi-bridge/src/config.rs lines 22-28
pub fn assert_valid(&self) {
    require!(self.fee_rate < MAX_RATIO, "Invalid fee_rate");
    require!(
        self.protocol_fee_rate <= MAX_RATIO,
        "Invalid protocol_fee_rate"
    );
}
```

`fee_min` is entirely unconstrained. [1](#0-0) 

`get_fee()` returns `max(amount * fee_rate / MAX_RATIO, fee_min)`:

```rust
// contracts/satoshi-bridge/src/config.rs lines 30-35
pub fn get_fee(&self, amount: u128) -> u128 {
    std::cmp::max(
        amount * u128::from(self.fee_rate) / u128::from(MAX_RATIO),
        self.fee_min,
    )
}
``` [2](#0-1) 

When `fee_min > amount`, `get_fee(amount)` returns `fee_min`, which is strictly greater than `amount`. Any downstream subtraction `amount - get_fee(amount)` underflows. Because the project enforces `overflow-checks = true`, this is a guaranteed panic rather than a silent wrap.

`Config.assert_valid()` validates several cross-field relationships (e.g., `min_change_amount < max_change_amount`, `min_btc_gas_fee < max_btc_gas_fee`) but never checks `withdraw_bridge_fee.fee_min <= min_withdraw_amount` or `deposit_bridge_fee.fee_min <= min_deposit_amount`: [3](#0-2) 

`ConfigUpdate.apply()` calls `config.assert_valid()` after applying changes, so the missing cross-validation is also absent at update time: [4](#0-3) 

Additional unbounded parameters with no lower-bound checks in `assert_valid()`:
- `refund_timelock_sec` — can be set to `0`, bypassing the security timelock entirely (only `refund_timelock_sec <= unsafe_refund_timelock_sec` is checked). [5](#0-4) 
- `max_withdrawal_input_number`, `max_change_number`, `rbf_num_limit`, `max_btc_tx_pending_sec` — all `u8`/`u32` fields with no `>= 1` lower bound. [6](#0-5) 

---

### Impact Explanation

**Low.** If `withdraw_bridge_fee.fee_min` is set above `min_withdraw_amount`, every withdrawal attempt at or near the minimum amount panics with an arithmetic underflow. The withdrawal path is stuck for all users until the DAO issues a corrective `update_config`. No direct theft occurs, but user funds are temporarily locked in the bridge (nBTC held, BTC not released) until operator intervention. This matches the allowed impact: *"Publicly reachable invariant-violation, stuck-state, or panic-driven fault in production bridge/token paths without direct theft."*

---

### Likelihood Explanation

Low. Requires the DAO to misconfigure `fee_min` to a value exceeding `min_withdraw_amount` — an unintentional but plausible error given that the two fields are set independently via `ConfigUpdate` and no validation ties them together. The report's analog (Reserve Protocol) demonstrates exactly this class of governance misconfiguration occurring in practice.

---

### Recommendation

Add cross-field validation inside `Config::assert_valid()`:

```rust
require!(
    self.withdraw_bridge_fee.fee_min <= self.min_withdraw_amount,
    "withdraw fee_min must not exceed min_withdraw_amount"
);
require!(
    self.deposit_bridge_fee.fee_min <= self.min_deposit_amount,
    "deposit fee_min must not exceed min_deposit_amount"
);
require!(
    self.refund_timelock_sec > 0,
    "refund_timelock_sec must be > 0"
);
require!(
    self.max_withdrawal_input_number >= 1,
    "max_withdrawal_input_number must be >= 1"
);
require!(
    self.max_change_number >= 1,
    "max_change_number must be >= 1"
);
``` [3](#0-2) 

---

### Proof of Concept

1. DAO calls `update_config` with `withdraw_bridge_fee: { fee_min: "100000", fee_rate: 0, protocol_fee_rate: 0 }` and `min_withdraw_amount: "1000"`.
2. `BridgeFee::assert_valid()` passes: `fee_rate (0) < 10000` ✓, `protocol_fee_rate (0) <= 10000` ✓. `fee_min` is never checked against `min_withdraw_amount`.
3. `Config::assert_valid()` passes: no cross-field check between `fee_min` and `min_withdraw_amount` exists.
4. A user calls `ft_transfer_call` on nBTC with `amount = 1000` (the minimum allowed).
5. The bridge calls `get_fee(1000)` → `max(1000 * 0 / 10000, 100000)` → `100000`.
6. The withdrawal code computes `amount - fee = 1000 - 100000`, which underflows.
7. With `overflow-checks = true`, the NEAR transaction panics. The user's nBTC is returned via the NEP-141 callback, but the withdrawal is permanently stuck until the DAO corrects `fee_min`. Any user attempting a withdrawal during this window hits the same panic. [2](#0-1) [1](#0-0)

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

**File:** contracts/satoshi-bridge/src/config.rs (L88-111)
```rust
    // The maximum number of inputs that can be used for a Withdraw.
    pub max_withdrawal_input_number: u8,
    // The maximum amount of change allowed during a Withdraw.
    pub max_change_number: u8,
    // The maximum number of inputs allowed during active UTXO management.
    pub max_active_utxo_management_input_number: u8,
    // The maximum number of outputs allowed during active UTXO management.
    pub max_active_utxo_management_output_number: u8,
    // When the number of UTXOs in the protocol is less than this configuration, UTXO management can be actively initiated.
    // The number of inputs in the managed PSBT must be less than the number of outputs.
    pub active_management_lower_limit: u32,
    // When the number of UTXOs in the protocol is greater than this configuration, UTXO management can be actively initiated.
    // The number of inputs in the managed PSBT must be greater than the number of outputs.
    pub active_management_upper_limit: u32,
    // When the number of UTXOs in the protocol is less than this configuration, passive UTXO management will be triggered,
    // requiring that the number of inputs must be less than the number of changes.
    pub passive_management_lower_limit: u32,
    // When the number of UTXOs in the protocol is greater than this configuration, passive UTXO management will be triggered,
    // requiring that the number of inputs must be greater than the number of changes.
    pub passive_management_upper_limit: u32,
    // The maximum number of transactions allowed to initiate RBF
    pub rbf_num_limit: u8,
    // If the transaction exceeds this configuration and has not been verified, the protocol will be allowed to cancel the transaction.
    pub max_btc_tx_pending_sec: u32,
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

**File:** contracts/satoshi-bridge/src/config.rs (L265-301)
```rust
impl ConfigUpdate {
    pub fn apply(self, config: &mut Config) {
        macro_rules! set_if_some {
            ($field:ident) => {
                if let Some(v) = self.$field {
                    config.$field = v;
                }
            };
        }
        set_if_some!(btc_light_client_account_id);
        set_if_some!(nbtc_account_id);
        set_if_some!(confirmations_delta);
        set_if_some!(extra_msg_confirmations_delta);
        set_if_some!(deposit_bridge_fee);
        set_if_some!(withdraw_bridge_fee);
        set_if_some!(min_deposit_amount);
        set_if_some!(min_withdraw_amount);
        set_if_some!(min_change_amount);
        set_if_some!(max_change_amount);
        set_if_some!(min_btc_gas_fee);
        set_if_some!(max_btc_gas_fee);
        set_if_some!(max_withdrawal_input_number);
        set_if_some!(max_change_number);
        set_if_some!(max_active_utxo_management_input_number);
        set_if_some!(max_active_utxo_management_output_number);
        set_if_some!(active_management_lower_limit);
        set_if_some!(active_management_upper_limit);
        set_if_some!(passive_management_lower_limit);
        set_if_some!(passive_management_upper_limit);
        set_if_some!(rbf_num_limit);
        set_if_some!(max_btc_tx_pending_sec);
        set_if_some!(unhealthy_utxo_amount);
        set_if_some!(refund_timelock_sec);
        set_if_some!(unsafe_refund_timelock_sec);

        config.assert_valid();
    }
```
