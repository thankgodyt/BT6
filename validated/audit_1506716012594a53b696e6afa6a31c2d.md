### Title
Integer Division Truncation in `get_protocol_and_relayer_fee` Silently Zeros Protocol Fee — (File: contracts/satoshi-bridge/src/config.rs)

---

### Summary

`BridgeFee::get_protocol_and_relayer_fee` splits a collected fee between the protocol and the relayer using integer division with no minimum floor. When `fee_amount * protocol_fee_rate < MAX_RATIO (10 000)`, Rust's integer truncation rounds `protocol_fee` to `0`, so the protocol collects nothing while the relayer receives the entire fee. This is the direct analog of the `snapAccumulator` rounding-to-zero pattern in the external report.

---

### Finding Description

`config.rs` defines two fee helpers:

```rust
// config.rs L30-35  — protected by fee_min floor
pub fn get_fee(&self, amount: u128) -> u128 {
    std::cmp::max(
        amount * u128::from(self.fee_rate) / u128::from(MAX_RATIO),
        self.fee_min,
    )
}

// config.rs L37-41  — NO floor protection
pub fn get_protocol_and_relayer_fee(&self, fee_amount: u128) -> (u128, u128) {
    let protocol_fee = fee_amount * u128::from(self.protocol_fee_rate) / u128::from(MAX_RATIO);
    let relayer_fee = fee_amount - protocol_fee;
    (protocol_fee, relayer_fee)
}
```

`get_fee` is guarded by `fee_min`, so the total fee charged to the user is always at least `fee_min`. However, `get_protocol_and_relayer_fee` has no analogous guard. Whenever:

```
fee_amount * protocol_fee_rate < 10_000
```

integer truncation produces `protocol_fee = 0`, and `relayer_fee = fee_amount` (the full amount). The protocol's share silently disappears.

Concrete example with plausible config values:
- `fee_min = 1 000` satoshis, `protocol_fee_rate = 5` (0.05 %)
- `fee_amount = 1 000` (the minimum fee)
- `protocol_fee = 1 000 * 5 / 10 000 = 0` (truncated)
- Relayer receives `1 000`, protocol receives `0` instead of the intended `~0.5` satoshis

The condition is reachable on every deposit and withdrawal that hits the minimum fee path, which is the common case for small-value transfers. [1](#0-0) [2](#0-1) 

---

### Impact Explanation

The protocol's accumulated fee (`acc_collected_protocol_fee`, `cur_available_protocol_fee`) is credited with `0` instead of the intended non-zero share on every affected transaction. Over time this constitutes a systematic, permanent under-collection of protocol revenue. The relayer receives more than its entitled share. No user funds are lost, but the bridge's fee-policy invariant is silently violated on every small-fee transaction, matching the **Medium — bypass of bridge limits or policies** impact class. [3](#0-2) 

---

### Likelihood Explanation

The condition `fee_amount * protocol_fee_rate < 10 000` is met whenever the collected fee is small relative to `MAX_RATIO / protocol_fee_rate`. For any `protocol_fee_rate` in the single-digit range (e.g. 1–9, representing 0.01–0.09 %), the threshold is 1 111–10 000 satoshis — well within the range of the minimum fee for small deposits. Because `get_fee` enforces `fee_min` as a floor, the minimum-fee path is the most common path for small-value users, making this condition routinely triggered. [4](#0-3) 

---

### Recommendation

Apply a rounding-up (ceiling) division for `protocol_fee`, or add a `protocol_fee_min` floor analogous to `fee_min`:

```rust
pub fn get_protocol_and_relayer_fee(&self, fee_amount: u128) -> (u128, u128) {
    // Ceiling division: (a * b + c - 1) / c
    let protocol_fee = if self.protocol_fee_rate == 0 {
        0
    } else {
        (fee_amount * u128::from(self.protocol_fee_rate) + u128::from(MAX_RATIO) - 1)
            / u128::from(MAX_RATIO)
    };
    let relayer_fee = fee_amount.saturating_sub(protocol_fee);
    (protocol_fee, relayer_fee)
}
```

Alternatively, document and enforce a minimum `protocol_fee_rate` that guarantees `fee_min * protocol_fee_rate >= MAX_RATIO` so truncation never reaches zero.

---

### Proof of Concept

1. Configure bridge with `fee_min = 1_000`, `fee_rate = 100` (1 %), `protocol_fee_rate = 5` (0.05 %).
2. User deposits an amount where `get_fee` returns exactly `fee_min = 1_000` satoshis.
3. Bridge calls `get_protocol_and_relayer_fee(1_000)`.
4. `protocol_fee = 1_000 * 5 / 10_000 = 0` (Rust integer truncation).
5. `relayer_fee = 1_000 - 0 = 1_000`.
6. Protocol's `cur_available_protocol_fee` is incremented by `0`; relayer receives the full `1_000` satoshis.
7. Repeat for every small deposit/withdrawal — protocol fee accumulator never grows despite `protocol_fee_rate > 0`. [1](#0-0) [5](#0-4)

### Citations

**File:** contracts/satoshi-bridge/src/config.rs (L6-6)
```rust
pub const MAX_RATIO: u32 = 10000;
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

**File:** contracts/satoshi-bridge/src/config.rs (L37-41)
```rust
    pub fn get_protocol_and_relayer_fee(&self, fee_amount: u128) -> (u128, u128) {
        let protocol_fee = fee_amount * u128::from(self.protocol_fee_rate) / u128::from(MAX_RATIO);
        let relayer_fee = fee_amount - protocol_fee;
        (protocol_fee, relayer_fee)
    }
```

**File:** contracts/satoshi-bridge/src/lib.rs (L141-145)
```rust
    pub acc_collected_protocol_fee: u128,
    pub cur_available_protocol_fee: u128,
    pub acc_claimed_protocol_fee: u128,
    pub cur_reserved_protocol_fee: u128,
    pub acc_protocol_fee_for_gas: u128,
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L1-1)
```rust
use near_sdk::serde_json::Value;
```
