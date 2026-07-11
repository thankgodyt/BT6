### Title
Single Global `max_btc_gas_fee` Applied Uniformly as Default Refund Gas Fee Causes Excessive User Fund Loss - (File: contracts/satoshi-bridge/src/bitcoin_utils/refund.rs)

### Summary

The Bitcoin bridge uses a single global `max_btc_gas_fee` configuration parameter as the default gas fee for refund transactions. This parameter is sized to accommodate large multi-input withdrawal transactions, but refund transactions always have exactly one input and one output — a structurally much smaller transaction. Any user who calls `request_refund` without specifying a custom `gas_fee` is silently charged the maximum withdrawal-sized fee for a minimal-sized transaction, causing them to receive significantly less BTC than they should.

### Finding Description

In `contracts/satoshi-bridge/src/bitcoin_utils/refund.rs`, the `get_refund_gas_fee()` function returns `max_btc_gas_fee` as the default refund gas fee:

```rust
pub(crate) fn get_refund_gas_fee(&self) -> u128 {
    self.internal_config().max_btc_gas_fee
}
``` [1](#0-0) 

This value is consumed in `request_refund_callback` when the caller omits `gas_fee`:

```rust
let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
require!(
    resolved_gas_fee < amount,
    "Gas fee must be less than deposit amount"
);
``` [2](#0-1) 

The only validation is that the fee is less than the deposit amount — there is no check that it is proportional to the actual transaction size.

Meanwhile, `max_btc_gas_fee` is the upper bound for withdrawal transactions, which can have up to `max_withdrawal_input_number` inputs (e.g., 10) and multiple change outputs:

```rust
require!(
    gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
    ...
);
``` [3](#0-2) 

A 10-input withdrawal transaction is roughly 10× larger than a 1-input refund transaction and legitimately requires a proportionally higher fee. The operator must set `max_btc_gas_fee` high enough to accommodate the largest withdrawal, but that same value becomes the default fee charged to every user who requests a refund without specifying a custom fee.

The `Config` struct defines both parameters as a single global pair with no per-transaction-type differentiation: [4](#0-3) 

### Impact Explanation

**Low.** A user who deposits BTC and later calls `request_refund` without specifying a `gas_fee` is charged `max_btc_gas_fee` — the maximum fee sized for a 10-input withdrawal — for a transaction that always has exactly 1 input and 1 output. If `max_btc_gas_fee` is configured at 50,000 satoshis (a reasonable ceiling for a 10-input withdrawal at ~50 sat/vbyte), a user depositing 100,000 satoshis receives only 50,000 satoshis back, losing 40,500 satoshis more than the ~9,500 satoshis a correctly-sized refund fee would cost. The excess fee is paid to Bitcoin miners, not stolen by an attacker, but the user suffers a real and significant fund loss through a publicly reachable code path. This is a publicly reachable invariant-violation in a production bridge path without direct theft.

### Likelihood Explanation

Any user who calls `request_refund` without supplying an explicit `gas_fee` argument triggers this path. The parameter is optional (`gas_fee: Option<u128>`), and the default is silently the maximum withdrawal fee. Users unfamiliar with the parameter or relying on the default will be affected every time they request a refund.

### Recommendation

Introduce a separate, transaction-size-aware default for refund gas fees. Since a Bitcoin refund always spends exactly one input and produces one output, the appropriate default can be computed from the actual transaction weight (analogous to how the Zcash variant uses `zip317_min_fee`):

```rust
// Bitcoin variant
pub(crate) fn get_refund_gas_fee(&self) -> u128 {
    // 1 input (~148 vbytes) + 1 P2PKH output (~34 vbytes) + overhead (~10 vbytes)
    // Use a configurable sat/vbyte rate, or a dedicated `refund_gas_fee` config field.
    self.internal_config().min_btc_gas_fee // or a dedicated refund_fee_rate * estimated_size
}
```

Alternatively, add a dedicated `refund_gas_fee` field to `Config` that is validated independently of `max_btc_gas_fee`, so operators can set an appropriate ceiling for each transaction type without the two constraints conflicting.

### Proof of Concept

1. Operator deploys bridge with `max_btc_gas_fee = 50_000` (sized for 10-input withdrawals at 50 sat/vbyte).
2. User deposits 100,000 satoshis to their derived deposit address.
3. Relayer does not call `verify_deposit` (e.g., relayer is down).
4. User calls `request_refund(deposit_msg, refund_address, tx_bytes, vout, proof, gas_fee: None)`.
5. `request_refund_callback` resolves `gas_fee = get_refund_gas_fee() = max_btc_gas_fee = 50_000`.
6. `RefundRequest` is stored with `gas_fee = 50_000`.
7. After the timelock, `execute_refund` builds a 1-input/1-output PSBT; `refund_amount = 100_000 - 50_000 = 50_000`.
8. User receives 50,000 satoshis instead of the ~90,500 satoshis they would receive with a correctly-sized fee.
9. The appropriate fee for a 1-input, 1-output P2PKH transaction at 50 sat/vbyte is approximately 9,500 satoshis — the user loses ~40,500 satoshis unnecessarily.

### Citations

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L7-12)
```rust
impl Contract {
    /// Default refund gas fee when the caller does not specify one. On Bitcoin the
    /// fee rate is unknown ahead of time, so we charge the configured maximum.
    pub(crate) fn get_refund_gas_fee(&self) -> u128 {
        self.internal_config().max_btc_gas_fee
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L549-553)
```rust
        let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
        require!(
            resolved_gas_fee < amount,
            "Gas fee must be less than deposit amount"
        );
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L252-258)
```rust
        require!(
            gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
            format!(
                "Invalid gas fee ({}). valid range: [{}, {}].",
                gas_fee, config.min_btc_gas_fee, config.max_btc_gas_fee
            )
        );
```

**File:** contracts/satoshi-bridge/src/config.rs (L83-87)
```rust
    #[serde(with = "u128_dec_format")]
    pub min_btc_gas_fee: u128,
    // The max gas fee applicable for Bitcoin transactions
    #[serde(with = "u128_dec_format")]
    pub max_btc_gas_fee: u128,
```
