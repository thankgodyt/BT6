### Title
`min_deposit_amount` Below `min_withdraw_amount` Permanently Prevents nBTC Redemption for Small Depositors - (File: contracts/satoshi-bridge/src/api/token_receiver.rs)

### Summary
The bridge enforces a `min_withdraw_amount` gate in `ft_on_transfer` but does not require `min_deposit_amount >= min_withdraw_amount` anywhere in configuration validation. Any user who deposits an amount between `min_deposit_amount` and `min_withdraw_amount` receives minted nBTC that can never be bridged back to BTC through the bridge's only withdrawal path.

### Finding Description
In `ft_on_transfer`, the bridge rejects any withdrawal attempt where the transferred nBTC amount is below `min_withdraw_amount`: [1](#0-0) 

This is the sole withdrawal entry point — there is no alternative path for a user to redeem nBTC for BTC. The configuration parameters `min_deposit_amount` and `min_withdraw_amount` are independent fields: [2](#0-1) 

The `assert_valid()` function enforces several cross-field invariants (e.g., `min_change_amount < max_change_amount`, `min_btc_gas_fee < max_btc_gas_fee`) but imposes **no constraint** that `min_deposit_amount >= min_withdraw_amount`: [3](#0-2) 

In the reference configuration used across both unit tests and integration tests, `min_deposit_amount = 20,000` satoshis while `min_withdraw_amount = 70,000` satoshis: [4](#0-3) 

A user who deposits any amount in the range `[20,000, 69,999]` satoshis will have nBTC minted to them that permanently fails the `ft_on_transfer` minimum check. The same condition arises from a `cancel_withdraw` RBF refund: the refund amount is `transfer_amount - withdraw_fee - burn_amount`, which can be below `min_withdraw_amount` for small withdrawals, and is sent back to the user via `internal_transfer_nbtc`: [5](#0-4) 

### Impact Explanation
Any user holding nBTC below `min_withdraw_amount` has no bridge-provided path to redeem their tokens for BTC. The nBTC is a freely transferable NEP-141 token (not locked in the bridge contract itself), but the bridge's only withdrawal mechanism is permanently blocked for that balance. The BTC backing those tokens remains in the bridge's UTXO pool indefinitely, inaccessible to the depositor. This constitutes a stuck bridge state requiring operator intervention (DAO governance to lower `min_withdraw_amount`) to resolve.

**Impact tier: Low** — publicly reachable stuck-state in the production bridge path without direct theft.

### Likelihood Explanation
Any unprivileged user who calls `nbtc.ft_transfer_call` with an amount in `[min_deposit_amount, min_withdraw_amount)` triggers this condition. With the reference configuration gap of 50,000 satoshis (~0.0005 BTC), small depositors are routinely affected. The condition is also reachable via cancel-withdraw refunds without any special access.

### Recommendation
Add a cross-field invariant in `Config::assert_valid()` requiring that `min_deposit_amount` is at least `min_withdraw_amount + withdraw_bridge_fee.fee_min + min_btc_gas_fee`. This ensures every successfully minted nBTC balance is large enough to be bridged back. Alternatively, document the gap explicitly and provide an operator-callable escape hatch (e.g., a privileged `force_withdraw` for sub-minimum balances) so users are never permanently stranded. [3](#0-2) 

### Proof of Concept
1. Bridge is deployed with `min_deposit_amount = 20,000` and `min_withdraw_amount = 70,000` (reference config).
2. Alice sends 30,000 satoshis to her deposit address on Bitcoin.
3. Relayer calls `verify_deposit`; the bridge mints 30,000 nBTC to Alice (deposit fee is 0 in reference config).
4. Alice calls `nbtc.ft_transfer_call(bridge_id, 30000, WithdrawMsg{...})`.
5. The nBTC contract calls `bridge.ft_on_transfer(alice, 30000, msg)`.
6. The bridge executes `require!(30000 >= 70000, "Invalid amount")` — this panics and the NEP-141 standard returns the full amount to Alice.
7. Alice's 30,000 nBTC is returned to her wallet but she has no other bridge path to redeem it for BTC. The condition is permanent unless the DAO lowers `min_withdraw_amount`. [1](#0-0) [2](#0-1)

### Citations

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L29-33)
```rust
        let amount = amount.into();
        require!(
            amount >= self.internal_config().min_withdraw_amount,
            "Invalid amount"
        );
```

**File:** contracts/satoshi-bridge/src/config.rs (L70-75)
```rust
    // The min amount must be met during verify_deposit, otherwise NBTC will not be minted for the user.
    #[serde(with = "u128_dec_format")]
    pub min_deposit_amount: u128,
    // The minimum amount allowed for the user to withdraw.
    #[serde(with = "u128_dec_format")]
    pub min_withdraw_amount: u128,
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

**File:** contracts/satoshi-bridge/src/unit/mod.rs (L63-65)
```rust
        min_deposit_amount: 20000,
        min_withdraw_amount: 70000,
        min_change_amount: 0,
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L62-68)
```rust
        let refund = if btc_pending_info.is_cancel_withdraw_rbf() {
            btc_pending_info
                .transfer_amount
                .saturating_sub(btc_pending_info.withdraw_fee + btc_pending_info.burn_amount)
        } else {
            0
        };
```
