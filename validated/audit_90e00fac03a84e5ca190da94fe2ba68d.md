### Title
Rounding-down in `BridgeFee::get_fee` allows complete fee bypass for small deposits/withdrawals — (File: contracts/satoshi-bridge/src/config.rs)

### Summary
`BridgeFee::get_fee` uses integer division that truncates toward zero. When `fee_min = 0` and a deposit or withdrawal amount is small enough that `amount * fee_rate < MAX_RATIO`, the computed fee rounds to zero. The deposit flow then mints the full deposit amount as nBTC with no fee deducted, and the withdrawal flow charges no bridge fee, bypassing the configured percentage fee entirely.

### Finding Description
In `config.rs`, the fee is computed as:

```rust
pub fn get_fee(&self, amount: u128) -> u128 {
    std::cmp::max(
        amount * u128::from(self.fee_rate) / u128::from(MAX_RATIO),
        self.fee_min,
    )
}
```

`MAX_RATIO = 10_000`. When `fee_min = 0`, the effective fee is `amount * fee_rate / 10_000`, which truncates. Any `amount < 10_000 / fee_rate` produces a fee of exactly `0`.

This result flows directly into the deposit path in `btc_light_client/deposit.rs`:

```rust
let deposit_fee = config.deposit_bridge_fee.get_fee(deposit_amount);
let mint_amount = deposit_amount - deposit_fee;   // deposit_fee == 0 → full amount minted
let (protocol_fee, relayer_fee) = config
    .deposit_bridge_fee
    .get_protocol_and_relayer_fee(deposit_fee);   // both == 0
```

The user receives `deposit_amount` nBTC with zero fee. The same `get_fee` call governs the withdrawal fee in `ft_on_transfer` → `check_withdraw_psbt`, so the same bypass applies on the withdrawal side.

`get_protocol_and_relayer_fee` compounds the issue: it also rounds down the protocol share of whatever fee was computed, so even non-zero fees lose 1 satoshi to rounding in favour of the relayer.

### Impact Explanation
When `fee_min = 0` and `fee_rate > 0`, any deposit or withdrawal whose satoshi value is below `10_000 / fee_rate` pays zero bridge fee. The