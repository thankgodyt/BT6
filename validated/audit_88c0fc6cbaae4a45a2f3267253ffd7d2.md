### Title
Deposit Fee Deduction Can Produce nBTC Balance Below `min_withdraw_amount`, Permanently Locking User Funds - (File: `contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

---

### Summary

A user can deposit BTC at or just above `min_deposit_amount` and receive minted nBTC whose value — after the bridge's deposit fee is deducted — falls below `min_withdraw_amount`. Because `ft_on_transfer` enforces `amount >= min_withdraw_amount` for every withdrawal, the user's nBTC becomes permanently unwithdrawable unless they acquire additional nBTC through other means.

---

### Finding Description

The deposit path in `internal_verify_deposit` mints `mint_amount = deposit_amount - deposit_fee` to the user, where `deposit_fee = max(deposit_amount * fee_rate / 10000, fee_min)`. [1](#0-0) 

The only gate on the deposit side is `deposit_amount >= min_deposit_amount`. There is no requirement that the post-fee `mint_amount` meets or exceeds `min_withdraw_amount`. [2](#0-1) 

On the withdrawal side, `ft_on_transfer` unconditionally requires:

```rust
require!(
    amount >= self.internal_config().min_withdraw_amount,
    "Invalid amount"
);
``` [3](#0-2) 

`Config::assert_valid()` enforces several cross-field invariants but contains **no check** that `min_deposit_amount - fee_min >= min_withdraw_amount`. [4](#0-3) 

---

### Impact Explanation

A user who deposits exactly `min_deposit_amount` satoshis receives `mint_amount = min_deposit_amount - deposit_fee` nBTC. If `deposit_fee` (dominated by `fee_min` for small deposits) is large enough that `mint_amount < min_withdraw_amount`, the user holds nBTC they can never redeem for BTC through the bridge's normal withdrawal path. The nBTC is not destroyed — it exists on-chain — but the bridge's own `ft_on_transfer` gate makes it permanently unwithdrawable without acquiring additional nBTC from an external source. This constitutes **permanent locking of bridged user funds**.

---

### Likelihood Explanation

The three parameters (`min_deposit_amount`, `deposit_bridge_fee.fee_min`, `min_withdraw_amount`) are independently configurable via `update_config` and carry no cross-field validation. A realistic configuration such as:

- `min_deposit_amount = 10_000` sat  
- `deposit_bridge_fee.fee_min = 5_000` sat  
- `min_withdraw_amount = 8_000` sat  

would cause every deposit of exactly `min_deposit_amount` to mint only `5_000` nBTC — below the `8_000` withdrawal floor. Any ordinary user depositing the advertised minimum would be affected. The attacker role here is simply a normal bridge user; no privilege is required.

---

### Recommendation

Add a cross-field invariant in `Config::assert_valid()`:

```rust
require!(
    self.min_deposit_amount
        .saturating_sub(self.deposit_bridge_fee.fee_min)
        >= self.min_withdraw_amount,
    "min_deposit_amount after fee_min must be >= min_withdraw_amount"
);
```

Alternatively, enforce a minimum deposit floor in the deposit path itself so that `mint_amount` is always at least `min_withdraw_amount` before minting proceeds. [4](#0-3) 

---

### Proof of Concept

1. DAO sets config: `min_deposit_amount = 10_000`, `deposit_bridge_fee = { fee_min: 6_000, fee_rate: 0, protocol_fee_rate: 0 }`, `min_withdraw_amount = 5_000`.
2. Alice sends exactly `10_000` sat to her deposit address on Bitcoin.
3. Relayer calls `verify_deposit_v2`. Since `10_000 >= min_deposit_amount`, the normal path executes: `deposit_fee = max(0, 6_000) = 6_000`; `mint_amount = 4_000`.
4. Alice receives `4_000` nBTC.
5. Alice calls `ft_transfer_call` on the nBTC contract with `amount = 4_000` and a `Withdraw` message.
6. Bridge's `ft_on_transfer` fires: `require!(4_000 >= 5_000)` → **panics with "Invalid amount"**. The transfer is refunded.
7. Alice's `4_000` nBTC is permanently unwithdrawable via the bridge. She cannot recover her BTC. [5](#0-4) [6](#0-5)

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L45-71)
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
            let (protocol_fee, relayer_fee) = config
                .deposit_bridge_fee
                .get_protocol_and_relayer_fee(deposit_fee);

            let post_actions = self.check_deposit_msg(deposit_msg, mint_amount);
            promise.then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_VERIFY_DEPOSIT_CALL_BACK)
                    .verify_deposit_callback(
                        recipient_id,
                        mint_amount.into(),
                        protocol_fee.into(),
                        relayer_fee.into(),
                        pending_utxo_info,
                        post_actions,
                    ),
            )
        }
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

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L29-33)
```rust
        let amount = amount.into();
        require!(
            amount >= self.internal_config().min_withdraw_amount,
            "Invalid amount"
        );
```
