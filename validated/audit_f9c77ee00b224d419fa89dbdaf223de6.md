### Title
Withdrawal Bridge Fee Is Calculated on Total nBTC Burned (Including BTC Network Gas Fee) Instead of Net Bridged Value - (File: contracts/satoshi-bridge/src/api/token_receiver.rs)

---

### Summary

In `create_btc_pending_info`, the bridge fee for a withdrawal is computed as `get_fee(amount)` where `amount` is the **total nBTC burned by the user**. That total includes the BTC network gas fee (`gas_fee`). The protocol intends to charge a percentage fee on the value actually bridged to the user, but instead charges it on a larger base that includes the on-chain gas cost, causing systematic overcharging on every rate-based withdrawal.

---

### Finding Description

The withdrawal flow is initiated when a user calls `ft_transfer_call` on the nBTC contract, which triggers `ft_on_transfer` in the bridge. The `amount` parameter is the total nBTC the user burns. Inside `create_btc_pending_info`:

```rust
// token_receiver.rs:89
let withdraw_fee = self.internal_config().withdraw_bridge_fee.get_fee(amount);
```

`get_fee` is defined as:

```rust
// config.rs:30-35
pub fn get_fee(&self, amount: u128) -> u128 {
    std::cmp::max(
        amount * u128::from(self.fee_rate) / u128::from(MAX_RATIO),
        self.fee_min,
    )
}
```

The PSBT validation in `check_withdraw_psbt` then establishes the accounting identity:

```rust
// psbt.rs:238,242
let gas_fee = total_input_amount - total_output_amount;
let max_received_amount = amount - withdraw_fee - gas_fee;
```

This confirms: `amount = actual_received_amount + withdraw_fee + gas_fee`.

The fee base therefore includes `gas_fee` — the BTC network transaction fee paid to miners — which is not value bridged to the user. The correct base for the bridge fee should be `amount - gas_fee` (i.e., the value the user actually receives plus the bridge fee itself), mirroring how the deposit side works: `deposit_fee = get_fee(deposit_amount)` where `deposit_amount` is the pure on-chain BTC value with no embedded network-fee component.

---

### Impact Explanation

Every withdrawal where the rate-based fee dominates over `fee_min` results in the user being overcharged by exactly:

```
overcharge = fee_rate * gas_fee / MAX_RATIO
```

For example, with `fee_rate = 100` (1 %) and `gas_fee = 10 000` satoshis (a typical BTC fee), the overcharge is **100 satoshis per withdrawal**. The excess is silently collected as additional protocol/relayer fee beyond what the fee schedule intends. Users have no way to avoid this because the `gas_fee` is a mandatory component of every withdrawal PSBT and is bounded only by `[min_btc_gas_fee, max_btc_gas_fee]`, both of which are non-zero by design.

This constitutes a publicly reachable invariant violation in the production withdrawal path: the fee charged does not match the documented fee model (percentage of bridged value), and the discrepancy grows with the BTC network gas fee.

**Allowed impact bucket:** Low — publicly reachable invariant-violation in a production bridge path without direct theft.

---

### Likelihood Explanation

**High.** The bug is triggered by every ordinary withdrawal where `fee_rate > 0` and the rate-based fee exceeds `fee_min`. Any unprivileged nBTC holder calling `ft_transfer_call` with a `Withdraw` message hits this path unconditionally. No special conditions, timing, or attacker knowledge is required.

---

### Recommendation

Compute the withdrawal fee on the net bridged base, excluding the BTC gas fee. Since `gas_fee` is not known until the PSBT is validated, one approach is a two-pass calculation:

1. Derive a provisional `gas_fee` from the submitted PSBT inputs/outputs before computing the fee.
2. Compute `withdraw_fee = get_fee(amount - gas_fee)`.
3. Re-validate the PSBT output amounts against the corrected fee.

Alternatively, define the fee base explicitly as `amount - gas_fee` and document it clearly in the `BridgeFee` struct, consistent with how `deposit_bridge_fee` operates on the pure deposited value.

---

### Proof of Concept

**Setup:** Configure `withdraw_bridge_fee` with `fee_rate = 100` (1 %), `fee_min = 0`, `protocol_fee_rate = 9000`.

**Withdrawal parameters:**
- `amount` (nBTC burned) = 200 000 satoshis
- `gas_fee` (BTC network fee, embedded in PSBT) = 10 000 satoshis
- `actual_received_amount` = 200 000 − withdraw_fee − 10 000

**Current behavior:**
```
withdraw_fee = get_fee(200_000) = 200_000 * 100 / 10_000 = 2_000 satoshis
actual_received_amount = 200_000 − 2_000 − 10_000 = 188_000 satoshis
```

**Correct behavior (fee on net bridged value):**
```
withdraw_fee = get_fee(200_000 − 10_000) = 190_000 * 100 / 10_000 = 1_900 satoshis
actual_received_amount = 200_000 − 1_900 − 10_000 = 188_100 satoshis
```

The user is overcharged **100 satoshis** (= `fee_rate * gas_fee / MAX_RATIO`). The overcharge accrues to `cur_available_protocol_fee` and `relayer_fee` beyond the intended schedule. At scale (e.g., 1 000 withdrawals/day with 10 000-sat gas fees), this amounts to 100 000 satoshis/day of unintended fee extraction from users.

The root cause is at: [1](#0-0) 

which calls: [2](#0-1) 

with a base that, as proven by: [3](#0-2) 

includes `gas_fee` — the BTC network fee — in addition to the net user-received value.

### Citations

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L89-89)
```rust
        let withdraw_fee = self.internal_config().withdraw_bridge_fee.get_fee(amount);
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

**File:** contracts/satoshi-bridge/src/psbt.rs (L238-242)
```rust
        let gas_fee = total_input_amount - total_output_amount;
        // When constructing the withdraw transaction, if the change is less than min_change_amount (dust),
        // the caller may deduct a portion from the user's output to make the change amount meet min_change_amount.
        // Therefore, the contract relaxes the validation.
        let max_received_amount = amount - withdraw_fee - gas_fee;
```
