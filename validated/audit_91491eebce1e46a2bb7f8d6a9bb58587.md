### Title
Protocol Fee Silently Truncates to Zero via Integer Division in `get_protocol_and_relayer_fee` — (File: contracts/satoshi-bridge/src/config.rs)

---

### Summary

`BridgeFee::get_protocol_and_relayer_fee` uses truncating integer division to split the collected bridge fee between the protocol treasury and the relayer. When the fee amount is small enough that `fee_amount * protocol_fee_rate < MAX_RATIO (10000)`, the protocol's share rounds to zero and the relayer captures 100% of the fee. Additionally, `get_fee` itself can produce zero when `fee_min = 0` and the deposit/withdrawal amount is below `MAX_RATIO / fee_rate`, meaning the user pays no fee at all. Neither `assert_valid` nor any other guard prevents `fee_min = 0`.

---

### Finding Description

In `contracts/satoshi-bridge/src/config.rs`, `BridgeFee` exposes two fee helpers:

```rust
// line 30-35
pub fn get_fee(&self, amount: u128) -> u128 {
    std::cmp::max(
        amount * u128::from(self.fee_rate) / u128::from(MAX_RATIO),
        self.fee_min,
    )
}

// line 37-41
pub fn get_protocol_and_relayer_fee(&self, fee_amount: u128) -> (u128, u128) {
    let protocol_fee = fee_amount * u128::from(self.protocol_fee_rate) / u128::from(MAX_RATIO);
    let relayer_fee = fee_amount - protocol_fee;
    (protocol_fee, relayer_fee)
}
```

`MAX_RATIO = 10000`. Both divisions truncate (Rust integer semantics).

**Issue A — `get_fee` returns 0 when `fee_min = 0`.**
`assert_valid` only checks `fee_rate < MAX_RATIO` and `protocol_fee_rate <= MAX_RATIO`; it places no lower bound on `fee_min`. When `fee_min = 0` and `fee_rate` is small, any deposit/withdrawal amount below `MAX_RATIO / fee_rate` produces `fee = 0`. For example, with `fee_rate = 1` (0.01 %) and `fee_min = 0`, every deposit below 10 000 satoshis pays zero fee.

**Issue B — `get_protocol_and_relayer_fee` rounds `protocol_fee` to 0 for small `fee_amount`.**
Even when `fee_min > 0` ensures a non-zero total fee, the protocol's share can still truncate to zero. With `fee_min = 1` satoshi and `protocol_fee_rate = 9000` (90 %): `1 * 9000 / 10000 = 0`. The relayer receives the entire fee; the protocol treasury receives nothing.

Both helpers are called on every deposit and withdrawal:
- Deposit path: `internal_verify_deposit` → `get_fee` then `get_protocol_and_relayer_fee` → `verify_deposit_callback` → `internal_mint_promise`.
- Withdrawal path: `verify_withdraw_burn_promise` → `get_protocol_and_relayer_fee` → `verify_withdraw_burn_callback` (which credits `cur_available_protocol_fee` only when `protocol_fee.0 > 0`).

---

### Impact Explanation

**Issue A**: When `fee_min = 0`, a user depositing or withdrawing at or near `min_deposit_amount` / `min_withdraw_amount` pays zero bridge fee. The protocol and relayer both receive nothing. This is a complete bypass of the fee policy for small-amount operations.

**Issue B**: Even with a non-zero `fee_min`, the protocol treasury is silently starved. Every deposit/withdrawal where `fee_min * protocol_fee_rate < MAX_RATIO` credits the relayer with 100 % of the fee and the protocol with 0. Over many transactions this constitutes a systematic, undetected diversion of protocol revenue to relayers.

Neither issue causes direct theft of user funds or unauthorized minting, but both constitute a bypass of the bridge's fee/revenue policy — matching the **Medium: Bypass of bridge limits or policies** impact class.

---

### Likelihood Explanation

- `fee_min = 0` is a valid on-chain configuration; `assert_valid` does not reject it. Any DAO-approved fee schedule with `fee_min = 0` and a small `fee_rate` immediately enables Issue A for every user depositing near the minimum.
- Issue B is configuration-independent in the sense that it triggers whenever `fee_min` is set to any value below `MAX_RATIO / protocol_fee_rate` (e.g., below 2 satoshis for a 90 % protocol split). This is a realistic operational range.
- The entry path is fully unprivileged: any NEAR account can call `verify_deposit` / `ft_transfer_call` with a deposit/withdrawal amount that exercises the rounding path.

---

### Recommendation

1. **Round up `protocol_fee`** in `get_protocol_and_relayer_fee` so the protocol always receives at least its intended share:
   ```rust
   let protocol_fee = (fee_amount * u128::from(self.protocol_fee_rate)
       + u128::from(MAX_RATIO) - 1)
       / u128::from(MAX_RATIO);
   ```
2. **Add a minimum-fee guard in `assert_valid`**: require `fee_min > 0` whenever `fee_rate > 0`, or enforce that `fee_min >= MAX_RATIO / fee_rate` so `get_fee` can never return 0 for any reachable deposit amount.
3. **Round up `get_fee`** analogously, or enforce the invariant via `fee_min`.

---

### Proof of Concept

**Issue A (zero total fee):**
- Configure: `fee_rate = 1`, `fee_min = 0`, `min_deposit_amount = 5000`.
- User deposits 5000 satoshis.
- `get_fee(5000)` = `max(5000 * 1 / 10000, 0)` = `max(0, 0)` = **0**.
- `mint_amount = 5000 - 0 = 5000`; protocol and relayer both receive 0.

**Issue B (zero protocol fee despite non-zero total fee):**
- Configure: `fee_rate = 200` (2 %), `fee_min = 1`, `protocol_fee_rate = 9000` (90 %).
- User deposits 49 satoshis (just above `min_deposit_amount`).
- `get_fee(49)` = `max(49 * 200 / 10000, 1)` = `max(0, 1)` = **1**.
- `get_protocol_and_relayer_fee(1)`: `protocol_fee = 1 * 9000 / 10000` = **0**; `relayer_fee = 1`.
- Protocol treasury receives 0 satoshis; relayer captures 100 % of the fee.
- `verify_withdraw_burn_callback` skips the `cur_available_protocol_fee` credit because `protocol_fee.0 == 0`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L135-138)
```rust
            if protocol_fee.0 > 0 {
                self.data_mut().acc_collected_protocol_fee += protocol_fee.0;
                self.data_mut().cur_available_protocol_fee += protocol_fee.0;
            }
```

**File:** contracts/satoshi-bridge/src/nbtc/mint.rs (L59-62)
```rust
            if protocol_fee.0 > 0 {
                self.data_mut().acc_collected_protocol_fee += protocol_fee.0;
                self.data_mut().cur_available_protocol_fee += protocol_fee.0;
            }
```
