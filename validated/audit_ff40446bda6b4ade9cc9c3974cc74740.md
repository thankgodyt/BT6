### Title
Fee Calculations Round Down in Both `get_fee` and `get_protocol_and_relayer_fee`, Leaking Value Away from Protocol - (File: contracts/satoshi-bridge/src/config.rs)

### Summary
`BridgeFee::get_fee` and `BridgeFee::get_protocol_and_relayer_fee` both use truncating (floor) integer division. This means the total fee charged to users is slightly less than intended, and within that fee the protocol's share is further rounded down in favor of the relayer. Every deposit and withdrawal triggers this path, making it publicly reachable with no privileged access required.

### Finding Description
In `contracts/satoshi-bridge/src/config.rs`, the `BridgeFee` struct exposes two fee-computation helpers:

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

Both divisions truncate toward zero (Rust's default integer division). `MAX_RATIO` is `10000`, so the truncation error is up to `9999/10000`, i.e. at most **1 satoshi** per call.

**Deposit path** (`contracts/satoshi-bridge/src/btc_light_client/deposit.rs`, lines 52–56):
```rust
let deposit_fee = config.deposit_bridge_fee.get_fee(deposit_amount);   // rounded DOWN
let mint_amount = deposit_amount - deposit_fee;                          // user gets 1 sat extra
let (protocol_fee, relayer_fee) = config
    .deposit_bridge_fee
    .get_protocol_and_relayer_fee(deposit_fee);                          // protocol_fee rounded DOWN again
```

**Withdrawal path** (`contracts/satoshi-bridge/src/nbtc/burn.rs`, lines 14–16):
```rust
let (protocol_fee, relayer_fee) = config
    .withdraw_bridge_fee
    .get_protocol_and_relayer_fee(btc_pending_info.withdraw_fee);        // protocol_fee rounded DOWN
```

Two independent rounding losses compound:
1. `get_fee` rounds the total fee down → user pays up to 1 sat less than the configured rate.
2. `get_protocol_and_relayer_fee` rounds `protocol_fee` down → the remainder (`relayer_fee = fee_amount - protocol_fee`) absorbs the truncated satoshi, so the relayer receives up to 1 sat more than its configured share at the protocol's expense.

### Impact Explanation
Each transaction leaks at most 1 satoshi from the protocol fee pool. Across a high-volume bridge this accumulates continuously. The deposit variant also causes `mint_amount` to be 1 satoshi higher than the strictly correct value, meaning nBTC supply is minted at a marginally higher rate than the fee schedule intends. This is a publicly reachable invariant violation in the core fee-accounting path: the protocol never collects its full configured share of fees.

Severity: **Low** — no direct theft, but a persistent, reachable invariant violation in production bridge/token paths.

### Likelihood Explanation
Every single deposit (`verify_deposit`) and withdrawal (`verify_withdraw`) invocation exercises both functions. No special role, leaked key, or attacker-controlled input is required; any ordinary bridge user triggers the rounding loss automatically.

### Recommendation
Round fees **up** (ceiling division) in favor of the protocol and fee recipients, matching the best practice described in the referenced Sudoswap fix:

```rust
// ceiling division helper
fn ceil_div(a: u128, b: u128) -> u128 {
    (a + b - 1) / b
}

pub fn get_fee(&self, amount: u128) -> u128 {
    std::cmp::max(
        ceil_div(amount * u128::from(self.fee_rate), u128::from(MAX_RATIO)),
        self.fee_min,
    )
}

pub fn get_protocol_and_relayer_fee(&self, fee_amount: u128) -> (u128, u128) {
    let protocol_fee = ceil_div(
        fee_amount * u128::from(self.protocol_fee_rate),
        u128::from(MAX_RATIO),
    );
    let relayer_fee = fee_amount - protocol_fee;
    (protocol_fee, relayer_fee)
}
```

This ensures the protocol always collects at least its configured share and that users cannot receive more nBTC than the fee schedule permits.

### Proof of Concept
Concrete numeric example with `fee_rate = 1` (0.01 %), `protocol_fee_rate = 9000` (90 %), `fee_min = 0`:

| Variable | Current (floor) | Correct (ceil) | Δ |
|---|---|---|---|
| `deposit_amount` | 9 999 sat | 9 999 sat | — |
| `get_fee` result | `9999*1/10000 = 0` | `ceil(9999/10000) = 1` | −1 sat fee |
| `mint_amount` | 9 999 sat | 9 998 sat | +1 sat nBTC over-minted |

With `fee_rate = 3000` (30 %), `protocol_fee_rate = 9000`, `deposit_amount = 10 003`:

| Variable | Current (floor) | Correct (ceil) | Δ |
|---|---|---|---|
| `deposit_fee` | `10003*3000/10000 = 3000` | `ceil(30009000/10000) = 3001` | −1 sat |
| `protocol_fee` | `3000*9000/10000 = 2700` | `ceil(27000000/10000) = 2700` | 0 |

With `deposit_amount = 10 001`, `fee_rate = 3000`, `protocol_fee_rate = 9001`:

| Variable | Current (floor) | Correct (ceil) | Δ |
|---|---|---|---|
| `deposit_fee` | `10001*3000/10000 = 3000` | `3001` | −1 sat |
| `protocol_fee` | `3000*9001/10000 = 2700` | `ceil(27003000/10000) = 2701` | −1 sat to protocol |

Both rounding losses are reachable on every public deposit or withdrawal call. [1](#0-0) [2](#0-1) [3](#0-2)

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
