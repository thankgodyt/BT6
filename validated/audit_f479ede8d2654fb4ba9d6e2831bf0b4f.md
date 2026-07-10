### Title
Protocol Fee Silently Rounds to Zero, Redirecting All Fee Revenue to Relayer - (File: contracts/satoshi-bridge/src/config.rs)

### Summary
`BridgeFee::get_protocol_and_relayer_fee` performs integer division without a minimum floor. When `fee_amount * protocol_fee_rate < MAX_RATIO (10000)`, `protocol_fee` truncates to zero and the entire collected fee is transferred to the relayer instead of being split. The protocol's `acc_collected_protocol_fee` and `cur_available_protocol_fee` counters are never incremented, permanently diverting the protocol's revenue share to the relayer on every such transaction.

### Finding Description

`BridgeFee` in `contracts/satoshi-bridge/src/config.rs` has two fee-splitting functions:

```rust
pub const MAX_RATIO: u32 = 10000;

pub fn get_fee(&self, amount: u128) -> u128 {
    std::cmp::max(
        amount * u128::from(self.fee_rate) / u128::from(MAX_RATIO),
        self.fee_min,   // ← floor protects total fee
    )
}

pub fn get_protocol_and_relayer_fee(&self, fee_amount: u128) -> (u128, u128) {
    let protocol_fee = fee_amount * u128::from(self.protocol_fee_rate) / u128::from(MAX_RATIO);
    let relayer_fee  = fee_amount - protocol_fee;   // ← NO floor; protocol_fee can be 0
    (protocol_fee, relayer_fee)
}
```

`get_fee` is protected by `fee_min`, so the total fee collected from the user is always at least `fee_min`. However, `get_protocol_and_relayer_fee` has no analogous floor. When `fee_amount * protocol_fee_rate < MAX_RATIO`, integer division truncates `protocol_fee` to `0`, and `relayer_fee` absorbs the entire `fee_amount`.

This function is called in both the deposit path:

```rust
// contracts/satoshi-bridge/src/btc_light_client/deposit.rs
let deposit_fee = config.deposit_bridge_fee.get_fee(deposit_amount);
let (protocol_fee, relayer_fee) = config
    .deposit_bridge_fee
    .get_protocol_and_relayer_fee(deposit_fee);
```

and the withdrawal path:

```rust
// contracts/satoshi-bridge/src/nbtc/burn.rs
let (protocol_fee, relayer_fee) = config
    .withdraw_bridge_fee
    .get_protocol_and_relayer_fee(btc_pending_info.withdraw_fee);
```

In both callbacks, the protocol counters are only updated when `protocol_fee.0 > 0`:

```rust
if protocol_fee.0 > 0 {
    self.data_mut().acc_collected_protocol_fee += protocol_fee.0;
    self.data_mut().cur_available_protocol_fee += protocol_fee.0;
}
```

When `protocol_fee` is zero, neither counter is updated, and the relayer receives the full fee via `nbtc::burn` or `nbtc::mint`.

### Impact Explanation

The protocol permanently loses its configured share of every deposit and withdrawal fee whenever `fee_amount * protocol_fee_rate < MAX_RATIO`. The lost revenue is silently redirected to the relayer. Because `acc_collected_protocol_fee` and `cur_available_protocol_fee` are never incremented for these transactions, the DAO can never recover the missing funds via `withdraw_protocol_fee`. This is a publicly reachable invariant-violation in the production bridge/token paths: the invariant that the protocol receives `protocol_fee_rate / MAX_RATIO` of every collected fee is broken without any error or revert.

**Impact: Low** — no user funds are lost; the total fee is still collected from the user. The harm is permanent diversion of protocol revenue to relayers.

### Likelihood Explanation

The condition `fee_amount * protocol_fee_rate < MAX_RATIO` is easily reached in normal operation:

- `fee_min = 1000` satoshis (a plausible minimum for small deposits)
- `protocol_fee_rate = 9` (0.09%, a plausible split)
- `fee_amount = 1000`
- `protocol_fee = 1000 * 9 / 10000 = 0` ← truncates to zero

Any deposit or withdrawal whose computed fee equals `fee_min` (i.e., the ratio-based fee is smaller than the minimum) will trigger this. Since `fee_min` is the floor for all small-amount transactions, this condition fires on every minimum-fee transaction. No special privilege is required; any bridge user submitting a deposit or withdrawal triggers the path.

**Likelihood: Medium** — occurs on every transaction where `fee_amount` is at or near `fee_min` with a small `protocol_fee_rate`.

### Recommendation

Apply a minimum-of-one-satoshi floor to `protocol_fee` when `protocol_fee_rate > 0` and `fee_amount > 0`, mirroring the `fee_min` guard in `get_fee`:

```rust
pub fn get_protocol_and_relayer_fee(&self, fee_amount: u128) -> (u128, u128) {
    let mut protocol_fee =
        fee_amount * u128::from(self.protocol_fee_rate) / u128::from(MAX_RATIO);
    if self.protocol_fee_rate > 0 && fee_amount > 0 && protocol_fee == 0 {
        protocol_fee = 1; // ensure at least 1 unit reaches the protocol
    }
    let relayer_fee = fee_amount - protocol_fee;
    (protocol_fee, relayer_fee)
}
```

Alternatively, validate during configuration (`assert_valid`) that `fee_min * protocol_fee_rate >= MAX_RATIO` so the split is always non-zero.

### Proof of Concept

**Configuration:**
- `deposit_bridge_fee.fee_min = 1000` satoshis
- `deposit_bridge_fee.fee_rate = 0` (flat minimum fee only)
- `deposit_bridge_fee.protocol_fee_rate = 9` (0.09%)

**Execution:**
1. User deposits 500,000 satoshis via `verify_deposit`.
2. `get_fee(500_000)` → `max(500_000 * 0 / 10_000, 1_000)` = **1,000** satoshis total fee.
3. `get_protocol_and_relayer_fee(1_000)` → `protocol_fee = 1_000 * 9 / 10_000 = 0`; `relayer_fee = 1_000`.
4. `mint` is called with `protocol_fee = 0`, `relayer_fee = 1_000`.
5. In `mint_callback`: `protocol_fee.0 > 0` is false → `acc_collected_protocol_fee` and `cur_available_protocol_fee` are **not updated**.
6. Relayer receives 1,000 satoshis of nBTC; protocol receives 0.
7. Repeated across all minimum-fee deposits/withdrawals, the protocol's revenue is permanently diverted. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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
