### Title
u128 Underflow in `check_withdraw_psbt` Blocks RBF for Small Withdrawals Near Fee Boundary — (`contracts/satoshi-bridge/src/psbt.rs`)

### Summary

In `check_withdraw_psbt`, the computation of `min_received_amount` performs an unchecked u128 subtraction that underflows when `max_received_amount < config.min_change_amount`. This is reachable via the public `WithdrawUserRbf` path when a user with a small-but-valid withdrawal submits an RBF PSBT with a higher gas fee, permanently blocking them from using RBF for that withdrawal.

### Finding Description

The vulnerable arithmetic is at lines 242–243 of `psbt.rs`:

```rust
let max_received_amount = amount - withdraw_fee - gas_fee;
let min_received_amount = max_received_amount - config.min_change_amount;  // ← no guard
``` [1](#0-0) 

There is no check that `max_received_amount >= config.min_change_amount` before the subtraction. The `config.assert_valid()` enforces no relationship between `min_withdraw_amount`, `max_btc_gas_fee`, `withdraw_fee`, and `min_change_amount`: [2](#0-1) 

**Concrete reachable scenario:**

| Parameter | Example value |
|---|---|
| `min_withdraw_amount` | 10,000 sat |
| `max_btc_gas_fee` | 5,000 sat |
| `withdraw_fee` | 1,000 sat |
| `min_change_amount` | 5,000 sat |
| `transfer_amount` | 10,000 sat |

- **Original withdrawal** (gas_fee = 1,000): `max_received_amount` = 8,000 > 5,000 → valid, passes.
- **RBF attempt** (gas_fee = 5,000): `max_received_amount` = 4,000 < 5,000 → underflow on line 243.

The RBF path calls `check_withdraw_rbf_psbt_valid` → `check_withdraw_psbt` with no additional guard: [3](#0-2) 

The `ft_on_transfer` entry point enforces `amount >= min_withdraw_amount` for the original withdrawal, but the RBF path (`internal_withdraw_rbf`) has no equivalent floor check for the higher gas fee scenario: [4](#0-3) 

### Impact Explanation

- **If overflow checks are disabled** (default release mode): `min_received_amount` wraps to near `u128::MAX`. The range check `actual_received_amount >= min_received_amount` always fails, and every RBF attempt is rejected with a misleading "out of valid range" error.
- **If overflow checks are enabled** (common in NEAR contracts): the WASM execution traps/panics, reverting the RBF call.

Either way, the user cannot submit any RBF for this withdrawal. They are stuck waiting for the original low-fee transaction to confirm or for the operator cancellation timeout (`max_btc_tx_pending_sec`). No funds are permanently lost, but the user's withdrawal is temporarily locked in a state they cannot self-rescue from.

### Likelihood Explanation

Reachable by any unprivileged user whose `transfer_amount` satisfies `transfer_amount - withdraw_fee - max_btc_gas_fee < min_change_amount`. This is a realistic configuration gap: `config.assert_valid()` does not enforce `min_withdraw_amount >= max_btc_gas_fee + withdraw_fee + min_change_amount`, so deployed configurations can silently permit this boundary.

### Recommendation

Add an explicit underflow guard before line 243:

```rust
let max_received_amount = amount - withdraw_fee - gas_fee;
require!(
    max_received_amount >= config.min_change_amount,
    "Received amount after fees is below min_change_amount"
);
let min_received_amount = max_received_amount - config.min_change_amount;
```

Additionally, add to `Config::assert_valid()`:

```rust
require!(
    self.min_withdraw_amount >= self.max_btc_gas_fee + self.min_change_amount,
    "min_withdraw_amount must cover max_btc_gas_fee + min_change_amount"
);
``` [5](#0-4) 

### Proof of Concept

```
transfer_amount = 10_000
withdraw_fee    = 1_000
gas_fee (RBF)   = 5_000   (≤ max_btc_gas_fee, passes gas check at line 252)
min_change_amount = 5_000

max_received_amount = 10_000 - 1_000 - 5_000 = 4_000
min_received_amount = 4_000 - 5_000           → underflow (wraps or panics)

→ check_withdraw_psbt reverts; user cannot submit RBF.
```

The gas fee check at lines 252–258 runs **after** the underflow at line 243, so it provides no protection. [6](#0-5)

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

**File:** contracts/satoshi-bridge/src/config.rs (L124-158)
```rust
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

**File:** contracts/satoshi-bridge/src/rbf/withdraw.rs (L23-31)
```rust
        let (_, _, actual_received_amount, gas_fee) = self.check_withdraw_psbt(
            withdraw_rbf_psbt,
            target_address,
            &withdraw_change_address_script_pubkey,
            &original_tx_btc_pending_info.vutxos,
            original_tx_btc_pending_info.transfer_amount,
            original_tx_btc_pending_info.withdraw_fee,
        );
        (actual_received_amount, gas_fee)
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L30-33)
```rust
        require!(
            amount >= self.internal_config().min_withdraw_amount,
            "Invalid amount"
        );
```
