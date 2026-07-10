### Title
Fee Calculation Rounds Down in Favor of Users, Slowly Draining Protocol Fee Revenue - (File: `contracts/satoshi-bridge/src/config.rs`)

### Summary
`BridgeFee::get_fee()` uses integer division (truncation/floor) to compute the bridge fee, rounding the result **down**. Because the fee is subtracted from the user's deposit or withdrawal amount, rounding the fee down means users receive slightly more nBTC (on deposit) or slightly more BTC (on withdrawal) than the protocol intends. Over many transactions this constitutes a persistent, publicly-triggerable invariant violation that silently erodes protocol fee revenue.

### Finding Description
In `contracts/satoshi-bridge/src/config.rs`, `BridgeFee::get_fee` computes:

```rust
pub fn get_fee(&self, amount: u128) -> u128 {
    std::cmp::max(
        amount * u128::from(self.fee_rate) / u128::from(MAX_RATIO),
        self.fee_min,
    )
}
```

Rust integer division truncates toward zero, so `amount * fee_rate / MAX_RATIO` always rounds **down**. The fee is then used in two places:

**Deposit path** (`contracts/satoshi-bridge/src/btc_light_client/deposit.rs`, line 52–53):
```rust
let deposit_fee = config.deposit_bridge_fee.get_fee(deposit_amount);
let mint_amount = deposit_amount - deposit_fee;
```
A rounded-down `deposit_fee` produces a rounded-up `mint_amount`, so the user receives 1 extra satoshi of nBTC per transaction where `deposit_amount * fee_rate` is not divisible by `MAX_RATIO`.

**Withdrawal path** (`contracts/satoshi-bridge/src/api/token_receiver.rs`, line 89):
```rust
let withdraw_fee = self.internal_config().withdraw_bridge_fee.get_fee(amount);
```
This `withdraw_fee` is then used in `check_withdraw_psbt` (`contracts/satoshi-bridge/src/psbt.rs`, line 242):
```rust
let max_received_amount = amount - withdraw_fee - gas_fee;
```
A rounded-down `withdraw_fee` allows the user's BTC output to be 1 satoshi higher than the protocol intends.

The same rounding direction issue exists in `get_protocol_and_relayer_fee` (line 38):
```rust
let protocol_fee = fee_amount * u128::from(self.protocol_fee_rate) / u128::from(MAX_RATIO);
let relayer_fee = fee_amount - protocol_fee;
```
Here `protocol_fee` is rounded down, so the relayer always receives the extra satoshi at the protocol's expense.

### Impact Explanation
Every deposit and withdrawal where `amount * fee_rate` is not divisible by `MAX_RATIO` (= 10000) causes the protocol to collect 1 satoshi less in fees than intended. The user receives 1 extra satoshi of nBTC or BTC. This is a persistent, per-transaction revenue leak. While each individual loss is tiny (≤ 1 satoshi), it is triggered by every ordinary user interaction and accumulates monotonically. The protocol's actual fee revenue will always be slightly below the configured rate, violating the fee-accounting invariant.

### Likelihood Explanation
This is triggered by every deposit and withdrawal where `amount * fee_rate % MAX_RATIO != 0`. With `MAX_RATIO = 10000` and arbitrary user-supplied amounts, this condition holds for the vast majority of transactions. No special attacker capability is required — any ordinary bridge user triggers it.

### Recommendation
Round the fee **up** instead of down to protect the protocol:

```rust
pub fn get_fee(&self, amount: u128) -> u128 {
    let rate_fee = (amount * u128::from(self.fee_rate) + u128::from(MAX_RATIO) - 1)
        / u128::from(MAX_RATIO);
    std::cmp::max(rate_fee, self.fee_min)
}

pub fn get_protocol_and_relayer_fee(&self, fee_amount: u128) -> (u128, u128) {
    // Round protocol_fee up so the protocol is never short-changed
    let protocol_fee = (fee_amount * u128::from(self.protocol_fee_rate)
        + u128::from(MAX_RATIO) - 1)
        / u128::from(MAX_RATIO);
    let relayer_fee = fee_amount - protocol_fee;
    (protocol_fee, relayer_fee)
}
```

### Proof of Concept
Suppose `fee_rate = 30` (0.3%), `MAX_RATIO = 10000`, and a user deposits `amount = 100001` satoshis.

- **Current code:** `fee = 100001 * 30 / 10000 = 3000030 / 10000 = 300` (truncated). `mint_amount = 100001 - 300 = 99701`.
- **Correct (rounded-up):** `fee = ceil(3000030 / 10000) = 301`. `mint_amount = 100001 - 301 = 99700`.

The user receives 1 extra satoshi of nBTC. With 10,000 such deposits per day, the protocol loses 10,000 satoshis (~0.0001 BTC) per day in fee revenue relative to its configured rate. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/config.rs (L30-35)
```rust
    pub fn get_fee(&self, amount: u128) -> u128 {
        std::cmp::max(
            amount * u128::from(self.fee_rate) / u128::from(MAX_RATIO),
            self.fee_min,
        )
    }
```

**File:** contracts/satoshi-bridge/src/config.rs (L37-41)
```rust
    pub fn get_protocol_and_relayer_fee(&self, fee_amount: u128) -> (u128, u128) {
        let protocol_fee = fee_amount * u128::from(self.protocol_fee_rate) / u128::from(MAX_RATIO);
        let relayer_fee = fee_amount - protocol_fee;
        (protocol_fee, relayer_fee)
    }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L52-53)
```rust
            let deposit_fee = config.deposit_bridge_fee.get_fee(deposit_amount);
            let mint_amount = deposit_amount - deposit_fee;
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L242-243)
```rust
        let max_received_amount = amount - withdraw_fee - gas_fee;
        let min_received_amount = max_received_amount - config.min_change_amount;
```
