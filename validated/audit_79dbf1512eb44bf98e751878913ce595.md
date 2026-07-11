### Title
Precision Loss in Fee Calculation Causes Protocol to Collect Less Than Intended Fee - (File: contracts/satoshi-bridge/src/config.rs)

### Summary
The `BridgeFee::get_fee` and `BridgeFee::get_protocol_and_relayer_fee` functions in `config.rs` perform integer division that rounds down, causing the protocol to collect less fee than the configured rate intends. Any bridge user can exploit this by choosing a withdrawal or deposit amount that maximizes the rounding benefit, saving up to `MAX_RATIO - 1 = 9999` satoshis per transaction.

### Finding Description
In `contracts/satoshi-bridge/src/config.rs`, the `BridgeFee` struct implements two fee-calculation methods:

```rust
pub fn get_fee(&self, amount: u128) -> u128 {
    std::cmp::max(
        amount * u128::from(self.fee_rate) / u128::from(MAX_RATIO),  // rounds down
        self.fee_min,
    )
}

pub fn get_protocol_and_relayer_fee(&self, fee_amount: u128) -> (u128, u128) {
    let protocol_fee = fee_amount * u128::from(self.protocol_fee_rate) / u128::from(MAX_RATIO);  // rounds down
    let relayer_fee = fee_amount - protocol_fee;
    (protocol_fee, relayer_fee)
}
```

`MAX_RATIO` is `10000` (basis points). Integer division truncates the remainder, so the actual fee collected is `floor(amount * fee_rate / 10000)` rather than the exact rational value. The maximum shortfall per call is `MAX_RATIO - 1 = 9999` satoshis.

`get_fee` is called for both deposit and withdrawal paths:
- Deposit: `contracts/satoshi-bridge/src/btc_light_client/deposit.rs` line 52 — `config.deposit_bridge_fee.get_fee(deposit_amount)`
- Withdrawal: `contracts/satoshi-bridge/src/api/token_receiver.rs` line 89 — `self.internal_config().withdraw_bridge_fee.get_fee(amount)`

`get_protocol_and_relayer_fee` is called during the burn callback in `contracts/satoshi-bridge/src/nbtc/burn.rs` lines 14–16, splitting the already-rounded fee between protocol and relayer with a second rounding step, compounding the loss to the protocol.

A user can choose an amount `N` such that `N * fee_rate mod MAX_RATIO = MAX_RATIO - 1`, maximising the rounding benefit on every transaction.

### Impact Explanation
The protocol and relayer collectively receive up to 9999 satoshis less per transaction than the configured fee rate intends. The `get_protocol_and_relayer_fee` split introduces a second rounding step, so the protocol treasury specifically loses up to an additional 9999 satoshis on top of the first loss. Over high transaction volume this constitutes a measurable, systematic undercollection of protocol revenue. No user funds are at risk; the impact is a publicly reachable invariant violation in the production fee-accounting path.

**Impact: Low** — publicly reachable invariant violation in production bridge/token paths without direct theft.

### Likelihood Explanation
Every deposit and withdrawal triggers `get_fee`. Any unprivileged user submitting a deposit proof or initiating a withdrawal can choose an amount that maximises the rounding shortfall. No special role or privileged access is required. The entry points (`verify_deposit` / `ft_on_transfer`) are fully public.

### Recommendation
Round up the fee instead of truncating:

```rust
pub fn get_fee(&self, amount: u128) -> u128 {
    let numerator = amount * u128::from(self.fee_rate);
    let denom = u128::from(MAX_RATIO);
    let fee = (numerator + denom - 1) / denom;   // ceiling division
    std::cmp::max(fee, self.fee_min)
}

pub fn get_protocol_and_relayer_fee(&self, fee_amount: u128) -> (u128, u128) {
    let denom = u128::from(MAX_RATIO);
    let protocol_fee = (fee_amount * u128::from(self.protocol_fee_rate) + denom - 1) / denom;
    let relayer_fee = fee_amount - protocol_fee;
    (protocol_fee, relayer_fee)
}
```

Ceiling division ensures the protocol never collects less than the configured rate.

### Proof of Concept
Assume `fee_rate = 30` (0.30 %), `MAX_RATIO = 10000`, `fee_min = 0`.

Choose `amount = 333_333` satoshis:
- Exact fee: `333_333 × 30 / 10_000 = 9_999.99` satoshis
- Collected fee (floor): `9_999` satoshis
- Shortfall: `1` satoshi (near-maximum for this rate)

Choose `amount = 333_333_333` satoshis (~3.33 BTC):
- Exact fee: `999_999.99` satoshis
- Collected fee (floor): `999_999` satoshis
- Shortfall: `1` satoshi

For `fee_rate = 1`, `amount = 9_999`:
- Exact fee: `0.9999` satoshis
- Collected fee (floor): `0` satoshis — full fee evaded when `fee_min = 0`

The second rounding in `get_protocol_and_relayer_fee` with `protocol_fee_rate = 9000`:
- `fee_amount = 9_999`, `protocol_fee = floor(9_999 × 9_000 / 10_000) = floor(8_999.1) = 8_999`
- Relayer receives `9_999 − 8_999 = 1_000` instead of the intended `999.9 → 1_000` (here relayer gains the rounding benefit at protocol's expense) [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L89-98)
```rust
        let withdraw_fee = self.internal_config().withdraw_bridge_fee.get_fee(amount);
        let (actual_received_amount, gas_fee) = self.check_withdraw_psbt_valid(
            target_btc_address.clone(),
            &withdraw_change_address_script_pubkey,
            &psbt,
            &vutxos,
            amount,
            withdraw_fee,
            max_gas_fee,
        );
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L14-16)
```rust
        let (protocol_fee, relayer_fee) = config
            .withdraw_bridge_fee
            .get_protocol_and_relayer_fee(btc_pending_info.withdraw_fee);
```
