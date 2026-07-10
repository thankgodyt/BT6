### Title
Fee Calculations Round Down in Favor of Users/Relayers Instead of Protocol - (File: contracts/satoshi-bridge/src/config.rs)

### Summary
`BridgeFee::get_fee` and `BridgeFee::get_protocol_and_relayer_fee` both use integer division (truncation), which rounds down. This means the bridge fee charged to users is slightly less than intended, and the protocol's share of that fee is also slightly less than intended. Value leaks from the protocol to users and relayers on every transaction where the division is not exact.

### Finding Description
In `contracts/satoshi-bridge/src/config.rs`, the `BridgeFee` struct implements two fee-calculation methods:

```rust
pub fn get_fee(&self, amount: u128) -> u128 {
    std::cmp::max(
        amount * u128::from(self.fee_rate) / u128::from(MAX_RATIO),
        self.fee_min,
    )
}

pub fn get_protocol_and_relayer_fee(&self, fee_amount: u128) -> (u128, u128) {
    let protocol_fee = fee_amount * u128::from(self.protocol_fee_rate) / u128::from(MAX_RATIO);
    let relayer_fee = fee_amount - protocol_fee;
    (protocol_fee, relayer_fee)
}
```

Both use Rust's integer division, which truncates toward zero (rounds down). There is no ceiling-division or rounding-up applied.

**`get_fee` path (deposit):** `deposit_fee = config.deposit_bridge_fee.get_fee(deposit_amount)` is rounded down, so `mint_amount = deposit_amount - deposit_fee` is rounded up — the user receives 1 extra satoshi of nBTC.

**`get_fee` path (withdrawal):** `withdraw_fee = self.internal_config().withdraw_bridge_fee.get_fee(amount)` is rounded down, so the user pays 1 less satoshi in fees.

**`get_protocol_and_relayer_fee` path:** `protocol_fee` is rounded down; the remainder goes to `relayer_fee = fee_amount - protocol_fee`, so the relayer receives 1 extra satoshi at the protocol's expense. This is called for both deposit (deposit.rs line 54–56) and withdrawal (burn.rs line 14–16).

### Impact Explanation
On every deposit or withdrawal where `amount * fee_rate` or `fee_amount * protocol_fee_rate` is not exactly divisible by `MAX_RATIO` (10000), the protocol collects up to 1 satoshi less than intended per calculation. Over high transaction volume this is a systematic, accumulating value leak from the protocol treasury to users and relayers. This is a publicly reachable invariant violation in production bridge/token paths without direct theft — **Low** severity.

### Likelihood Explanation
Any transaction where the fee arithmetic produces a non-zero remainder triggers the issue. With a non-zero `fee_rate` (e.g., `fee_rate = 1000`) and an arbitrary deposit amount, the remainder is non-zero for the majority of amounts. The `get_protocol_and_relayer_fee` path is similarly affected whenever `fee_min` or the rate-derived fee is not a multiple of `MAX_RATIO / gcd(protocol_fee_rate, MAX_RATIO)`. The current default `fee_rate = 0` avoids the `get_fee` truncation, but the DAO can set any `fee_rate < MAX_RATIO`, and `get_protocol_and_relayer_fee` is always susceptible when `fee_min` is not a multiple of 10.

### Recommendation
Use ceiling division for all fee calculations to ensure the protocol and fee recipients receive at least their intended share:

```rust
// Ceiling division helper
fn div_ceil(a: u128, b: u128) -> u128 {
    (a + b - 1) / b
}

pub fn get_fee(&self, amount: u128) -> u128 {
    std::cmp::max(
        div_ceil(amount * u128::from(self.fee_rate), u128::from(MAX_RATIO)),
        self.fee_min,
    )
}

pub fn get_protocol_and_relayer_fee(&self, fee_amount: u128) -> (u128, u128) {
    let protocol_fee = div_ceil(fee_amount * u128::from(self.protocol_fee_rate), u128::from(MAX_RATIO));
    let relayer_fee = fee_amount - protocol_fee;
    (protocol_fee, relayer_fee)
}
```

### Proof of Concept
**`get_fee` truncation:**
- `fee_rate = 1000`, `amount = 10001`
- Current: `10001 * 1000 / 10000 = 1000` (exact result is 1000.1, truncated)
- User receives `10001 - 1000 = 10001` satoshis of nBTC instead of `10001 - 1001 = 10000`
- Protocol+relayer lose 1 satoshi

**`get_protocol_and_relayer_fee` truncation:**
- `protocol_fee_rate = 9000`, `fee_amount = 10001`
- Current: `protocol_fee = 10001 * 9000 / 10000 = 9000` (exact result is 9000.9, truncated)
- `relayer_fee = 10001 - 9000 = 1001` (exact share is 1000.1)
- Protocol loses 1 satoshi; relayer gains 1 satoshi

Both truncations are reachable by any unprivileged user submitting a deposit proof or initiating a withdrawal via `ft_on_transfer`. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** contracts/satoshi-bridge/src/config.rs (L30-41)
```rust
    pub fn get_fee(&self, amount: u128) -> u128 {
        std::cmp::max(
            amount * u128::from(self.fee_rate) / u128::from(MAX_RATIO),
            self.fee_min,
        )
    }

    pub fn get_protocol_and_relayer_fee(&self, fee_amount: u128) -> (u128, u128) {
        let protocol_fee = fee_amount * u128::from(self.protocol_fee_rate) / u128::from(MAX_RATIO);
        let relayer_fee = fee_amount - protocol_fee;
        (protocol_fee, relayer_fee)
    }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L52-56)
```rust
            let deposit_fee = config.deposit_bridge_fee.get_fee(deposit_amount);
            let mint_amount = deposit_amount - deposit_fee;
            let (protocol_fee, relayer_fee) = config
                .deposit_bridge_fee
                .get_protocol_and_relayer_fee(deposit_fee);
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L14-16)
```rust
        let (protocol_fee, relayer_fee) = config
            .withdraw_bridge_fee
            .get_protocol_and_relayer_fee(btc_pending_info.withdraw_fee);
```
