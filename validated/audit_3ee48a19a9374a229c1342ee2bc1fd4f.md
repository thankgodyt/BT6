### Title
Protocol Fee Share Truncates to Zero via Integer Division in `get_protocol_and_relayer_fee` — (File: `contracts/satoshi-bridge/src/config.rs`)

---

### Summary

The `get_protocol_and_relayer_fee` function in `config.rs` computes the protocol's share of the bridge fee using integer division that truncates toward zero. When `fee_amount * protocol_fee_rate < MAX_RATIO (10 000)`, the protocol fee rounds to exactly `0`, and the relayer receives the entire fee. This is a direct Rust analog of the BarnBridge truncation bug: any deposit or withdrawal whose total fee falls below the rounding threshold silently pays the protocol nothing, regardless of the configured `protocol_fee_rate`.

---

### Finding Description

`BridgeFee::get_protocol_and_relayer_fee` splits a collected fee between the protocol treasury and the relayer:

```rust
pub fn get_protocol_and_relayer_fee(&self, fee_amount: u128) -> (u128, u128) {
    let protocol_fee = fee_amount * u128::from(self.protocol_fee_rate) / u128::from(MAX_RATIO);
    let relayer_fee = fee_amount - protocol_fee;
    (protocol_fee, relayer_fee)
}
``` [1](#0-0) 

`MAX_RATIO` is `10_000`. [2](#0-1) 

The total fee passed in is produced by `get_fee`:

```rust
pub fn get_fee(&self, amount: u128) -> u128 {
    std::cmp::max(
        amount * u128::from(self.fee_rate) / u128::from(MAX_RATIO),
        self.fee_min,
    )
}
``` [3](#0-2) 

`get_fee` has a `fee_min` floor, so the *total* fee is at least `fee_min`. However, `get_protocol_and_relayer_fee` performs a second integer division on that already-floored value. When:

```
fee_amount * protocol_fee_rate < MAX_RATIO
```

the division truncates to `0`, so `protocol_fee = 0` and `relayer_fee = fee_amount`. The protocol receives nothing.

**Concrete example:**
- `fee_min = 500` satoshis (the minimum fee floor)
- `protocol_fee_rate = 19` (≈ 0.19 %)
- `protocol_fee = 500 * 19 / 10_000 = 9_500 / 10_000 = 0` (truncated)
- Relayer receives all 500 satoshis; protocol receives 0.

The `assert_valid` guard on `BridgeFee` enforces only that `fee_rate < MAX_RATIO` and `protocol_fee_rate <= MAX_RATIO`; it places **no lower bound on `fee_min`** and no requirement that `fee_min * protocol_fee_rate >= MAX_RATIO`. [4](#0-3) 

The withdrawal path explicitly calls `get_fee` to compute the fee that is subsequently split:

```rust
let withdraw_fee = self.internal_config().withdraw_bridge_fee.get_fee(amount);
``` [5](#0-4) 

The same pattern applies to the deposit fee path via `deposit_bridge_fee`. [6](#0-5) 

---

### Impact Explanation

Every deposit and withdrawal whose `fee_amount * protocol_fee_rate < 10_000` silently credits the protocol treasury `0` satoshis. The relayer captures the full fee. Over many transactions at or near `fee_min`, the protocol accumulates zero revenue from its configured share. This is a systematic, permanent bypass of the protocol fee policy — the `acc_collected_protocol_fee` and `cur_available_protocol_fee` accumulators are never incremented for the protocol's portion. [7](#0-6) 

**Impact class:** Medium — Bypass of bridge fee policy without direct theft of user funds.

---

### Likelihood Explanation

The condition `fee_amount * protocol_fee_rate < 10_000` is easily satisfied in practice:

- Any `fee_min` below `10_000 / protocol_fee_rate` satoshis triggers it unconditionally for every transaction that hits the floor.
- With a typical `protocol_fee_rate` of 100–500 (1–5 %) and a `fee_min` of 100–500 satoshis (common dust-avoidance values), the product is well below 10 000.
- No special attacker action is required: every ordinary user deposit and withdrawal at or near the minimum fee silently zeroes the protocol share.
- The `ft_on_transfer` withdrawal entry point is publicly callable by any nBTC holder. [8](#0-7) 

---

### Recommendation

Round the protocol fee **up** (ceiling division) so the protocol always receives at least 1 satoshi when `protocol_fee_rate > 0` and `fee_amount > 0`:

```rust
pub fn get_protocol_and_relayer_fee(&self, fee_amount: u128) -> (u128, u128) {
    // Ceiling division: round in the protocol's favour
    let protocol_fee = (fee_amount * u128::from(self.protocol_fee_rate)
        + u128::from(MAX_RATIO) - 1)
        / u128::from(MAX_RATIO);
    let relayer_fee = fee_amount - protocol_fee;
    (protocol_fee, relayer_fee)
}
```

Additionally, add a validation in `BridgeFee::assert_valid` that enforces `fee_min * protocol_fee_rate >= MAX_RATIO` (or simply `fee_min > 0`) so the configuration itself cannot produce a zero protocol share.

---

### Proof of Concept

1. Protocol is configured with `fee_min = 500`, `fee_rate = 30` (0.3 %), `protocol_fee_rate = 19` (0.19 %).
2. User calls `ft_transfer_call` on the nBTC contract with `amount = min_withdraw_amount` (e.g. 1 000 satoshis).
3. Bridge computes `withdraw_fee = get_fee(1_000) = max(1_000 * 30 / 10_000, 500) = max(3, 500) = 500`.
4. Bridge calls `get_protocol_and_relayer_fee(500)`:
   - `protocol_fee = 500 * 19 / 10_000 = 9_500 / 10_000 = 0` ← truncated to zero.
   - `relayer_fee = 500 - 0 = 500`.
5. Protocol treasury receives 0 satoshis; relayer receives 500 satoshis.
6. Repeated across all deposits and withdrawals at or near `fee_min`, the protocol accumulates zero revenue from its configured 0.19 % share.

### Citations

**File:** contracts/satoshi-bridge/src/config.rs (L6-6)
```rust
pub const MAX_RATIO: u32 = 10000;
```

**File:** contracts/satoshi-bridge/src/config.rs (L21-28)
```rust
impl BridgeFee {
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

**File:** contracts/satoshi-bridge/src/config.rs (L37-41)
```rust
    pub fn get_protocol_and_relayer_fee(&self, fee_amount: u128) -> (u128, u128) {
        let protocol_fee = fee_amount * u128::from(self.protocol_fee_rate) / u128::from(MAX_RATIO);
        let relayer_fee = fee_amount - protocol_fee;
        (protocol_fee, relayer_fee)
    }
```

**File:** contracts/satoshi-bridge/src/config.rs (L67-68)
```rust
    pub deposit_bridge_fee: BridgeFee,
    // Used to calculate the withdraw fee.
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L23-33)
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
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L89-89)
```rust
        let withdraw_fee = self.internal_config().withdraw_bridge_fee.get_fee(amount);
```

**File:** contracts/satoshi-bridge/src/lib.rs (L141-145)
```rust
    pub acc_collected_protocol_fee: u128,
    pub cur_available_protocol_fee: u128,
    pub acc_claimed_protocol_fee: u128,
    pub cur_reserved_protocol_fee: u128,
    pub acc_protocol_fee_for_gas: u128,
```
