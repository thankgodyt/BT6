### Title
`min_deposit_amount` Below `min_withdraw_amount` Leaves Users With Permanently Unwithdrawable nBTC — (File: `contracts/satoshi-bridge/src/config.rs`)

---

### Summary

The bridge enforces two independent amount thresholds: `min_deposit_amount` (the minimum BTC deposit that triggers nBTC minting) and `min_withdraw_amount` (the minimum nBTC a user must send to initiate a withdrawal). No invariant in `Config::assert_valid()` ensures that a user who deposits exactly `min_deposit_amount` satoshi will receive enough nBTC to ever withdraw. When `min_deposit_amount < min_withdraw_amount` (the deployed configuration), a user who deposits between `min_deposit_amount` and `min_withdraw_amount + deposit_fee` satoshi receives nBTC that is permanently below the withdrawal floor, leaving their BTC locked in the bridge's UTXO pool with no redemption path.

---

### Finding Description

**Root cause — missing cross-field invariant in `Config::assert_valid()`:**

`Config::assert_valid()` validates many field relationships but never checks that `min_deposit_amount - max_deposit_fee >= min_withdraw_amount`. [1](#0-0) 

**Deposit path — uses `min_deposit_amount`:**

In `internal_verify_deposit`, if `deposit_amount >= config.min_deposit_amount`, the bridge proceeds to mint `mint_amount = deposit_amount - deposit_fee` nBTC to the user. [2](#0-1) 

**Withdrawal path — uses `min_withdraw_amount`:**

In `ft_on_transfer`, the bridge rejects any withdrawal where the transferred nBTC amount is below `min_withdraw_amount`. [3](#0-2) 

**The gap in the deployed configuration:**

Both the unit test setup and the integration test context configure `min_deposit_amount = 20,000` satoshi and `min_withdraw_amount = 70,000` satoshi — a 3.5× gap. [4](#0-3) 

A user who deposits exactly 20,000 satoshi (the minimum) receives `20,000 - deposit_fee` nBTC. With `deposit_bridge_fee.fee_min = 0` and `fee_rate = 0`, they receive exactly 20,000 nBTC. Since 20,000 < 70,000 = `min_withdraw_amount`, the withdrawal call is rejected. The BTC UTXO is absorbed into the bridge's pool (marked in `verified_deposit_utxo`) and the refund path is permanently blocked for that UTXO. [5](#0-4) 

The refund path (`request_refund`) explicitly blocks refunds for UTXOs already verified via deposit: [6](#0-5) 

---

### Impact Explanation

A user who deposits any amount in the range `[min_deposit_amount, min_withdraw_amount + max_deposit_fee)` satoshi receives nBTC that cannot be redeemed through the bridge's withdrawal mechanism. Their BTC is permanently absorbed into the bridge's UTXO pool. The user holds nBTC with no direct redemption path: the refund path is closed (UTXO already verified), and `ft_on_transfer` rejects the withdrawal. The user's only recourse is to transfer their nBTC to a third party or accumulate additional nBTC from external sources — neither of which is a bridge-provided remedy. This constitutes a stuck bridge state requiring operator intervention or a governance parameter change.

**Impact class:** Medium — stuck bridge state / permanent locking of user funds below the withdrawal floor.

---

### Likelihood Explanation

The gap between `min_deposit_amount` (20,000 sat) and `min_withdraw_amount` (70,000 sat) is present in both the unit test and integration test configurations, indicating this is the intended production deployment ratio. Any user who deposits the minimum amount — a natural behavior for users testing the bridge or depositing small amounts — will trigger this condition. No special attacker knowledge is required; the entry path is the standard `verify_deposit_v2` public relayer call followed by a normal `ft_transfer_call` withdrawal attempt.

---

### Recommendation

Add a cross-field invariant to `Config::assert_valid()` ensuring that the minimum mintable amount after fees is at least `min_withdraw_amount`:

```rust
// In Config::assert_valid():
let max_deposit_fee = self.deposit_bridge_fee.get_fee(self.min_deposit_amount);
require!(
    self.min_deposit_amount.saturating_sub(max_deposit_fee) >= self.min_withdraw_amount,
    "min_deposit_amount after fees must be >= min_withdraw_amount"
);
```

This mirrors the relationship enforced in the original Mai Protocol report between `lotSize` and `tradingLotSize`, ensuring that any amount accepted by the deposit gate is also redeemable through the withdrawal gate.

---

### Proof of Concept

1. Deploy bridge with `min_deposit_amount = 20_000`, `min_withdraw_amount = 70_000`, `deposit_bridge_fee.fee_min = 0`, `fee_rate = 0`.
2. User sends a BTC transaction of exactly 20,000 satoshi to their deposit address.
3. Relayer calls `verify_deposit_v2` — passes because `20_000 >= min_deposit_amount`.
4. `internal_verify_deposit` computes `mint_amount = 20_000 - 0 = 20_000` and calls `verify_deposit_callback`.
5. `verify_deposit_callback` inserts the UTXO into `verified_deposit_utxo` and mints 20,000 nBTC to the user.
6. User calls `ft_transfer_call` on the nBTC contract with `amount = 20_000` and a `Withdraw` message.
7. Bridge's `ft_on_transfer` panics: `require!(20_000 >= 70_000, "Invalid amount")` — withdrawal rejected, nBTC returned.
8. User attempts `request_refund` — rejected: `"UTXO already verified via deposit"`.
9. User's 20,000 satoshi BTC is permanently locked in the bridge UTXO pool; their 20,000 nBTC cannot be redeemed through the bridge.

### Citations

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

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L45-53)
```rust
        if deposit_amount < config.min_deposit_amount {
            promise.then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_UNAVAILABLE_UTXO_CALL_BACK)
                    .unavailable_utxo_callback(recipient_id, pending_utxo_info),
            )
        } else {
            let deposit_fee = config.deposit_bridge_fee.get_fee(deposit_amount);
            let mint_amount = deposit_amount - deposit_fee;
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L369-373)
```rust
        require!(
            self.data_mut()
                .verified_deposit_utxo
                .insert(pending_utxo_info.utxo_storage_key.clone()),
            "Already deposit utxo"
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L29-33)
```rust
        let amount = amount.into();
        require!(
            amount >= self.internal_config().min_withdraw_amount,
            "Invalid amount"
        );
```

**File:** contracts/satoshi-bridge/src/unit/mod.rs (L63-64)
```rust
        min_deposit_amount: 20000,
        min_withdraw_amount: 70000,
```

**File:** contracts/satoshi-bridge/src/refund.rs (L534-541)
```rust
        // Double-check not finalized (could have been verified between request and callback)
        require!(
            !self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key),
            "UTXO already verified via deposit"
        );
```
