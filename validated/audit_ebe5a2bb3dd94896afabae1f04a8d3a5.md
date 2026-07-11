### Title
Arithmetic Underflow in `check_withdraw_psbt` Causes Panic-Driven DoS on Valid Withdrawals - (File: contracts/satoshi-bridge/src/psbt.rs)

### Summary
In `check_withdraw_psbt`, the computation of `min_received_amount` performs an unchecked subtraction that panics when `max_received_amount < config.min_change_amount`. Because the project compiles with `overflow-checks = true`, this underflow is a hard panic, not a silent wrap. Any user whose withdrawal parameters land in this gap triggers a contract panic, reverting the entire `ft_on_transfer` call and permanently blocking that withdrawal attempt.

### Finding Description
Inside `check_withdraw_psbt` in `contracts/satoshi-bridge/src/psbt.rs`, the following two lines compute the acceptable range for the user's received amount:

```rust
let max_received_amount = amount - withdraw_fee - gas_fee;
let min_received_amount = max_received_amount - config.min_change_amount;
``` [1](#0-0) 

`max_received_amount` is the user's net BTC after the bridge fee and the on-chain gas fee are deducted. `min_received_amount` is then set `min_change_amount` below that, to allow the relayer to shave a dust amount off the user output when constructing change. If `max_received_amount < config.min_change_amount`, the subtraction on line 243 underflows and panics.

The bridge fee is computed by `BridgeFee::get_fee`:

```rust
pub fn get_fee(&self, amount: u128) -> u128 {
    std::cmp::max(
        amount * u128::from(self.fee_rate) / u128::from(MAX_RATIO),
        self.fee_min,
    )
}
``` [2](#0-1) 

When `fee_min` dominates (i.e., the proportional fee is smaller than `fee_min`), `withdraw_fee = fee_min`. Combined with the minimum on-chain gas fee (`min_btc_gas_fee`), the net amount left for the user is:

```
max_received_amount = amount - fee_min - min_btc_gas_fee
```

If this value is less than `min_change_amount`, the subtraction on line 243 panics. The `Config::assert_valid` function does not enforce the invariant `min_withdraw_amount >= fee_min + max_btc_gas_fee + min_change_amount`: [3](#0-2) 

So the gap can exist in a live deployment.

The security model explicitly states that `overflow-checks = true` is relied upon to catch unexpected arithmetic:

> "The project compiles with `overflow-checks = true` to ensure any unexpected overflow results in a panic."

This means the underflow is a guaranteed hard panic, not a silent wrap.

### Impact Explanation
The panic occurs inside `check_withdraw_psbt_valid` → `check_withdraw_psbt`, which is called from `create_btc_pending_info`, which is called from `ft_on_transfer_withdraw_chain_specific`, which is called from `ft_on_transfer`. Because the panic unwinds the entire NEAR transaction, the user's nBTC tokens are returned (no permanent loss). However, the withdrawal is permanently blocked for any `(amount, gas_fee)` pair that falls in the gap: the user cannot withdraw their BTC. This is a publicly reachable panic-driven fault in the production withdrawal path. [4](#0-3) 

### Likelihood Explanation
The condition is reachable whenever:
- `fee_min` is set to a significant fraction of `min_withdraw_amount` (e.g., to discourage micro-withdrawals), AND
- `min_withdraw_amount - fee_min - min_btc_gas_fee < min_change_amount`

No privileged access is required. Any user calling `ft_transfer_call` on the nBTC contract with a `Withdraw` message and an `amount` in the vulnerable range triggers the panic. The user controls `amount` (must be ≥ `min_withdraw_amount`) and the PSBT outputs (which determine `gas_fee`). Setting `gas_fee` to `min_btc_gas_fee` and `amount` to `min_withdraw_amount` is the minimal trigger.

### Recommendation
Add an explicit underflow guard before computing `min_received_amount`:

```rust
let max_received_amount = amount - withdraw_fee - gas_fee;
require!(
    max_received_amount >= config.min_change_amount,
    format!(
        "Net received amount ({}) is less than min_change_amount ({})",
        max_received_amount, config.min_change_amount
    )
);
let min_received_amount = max_received_amount - config.min_change_amount;
```

Additionally, add an invariant check in `Config::assert_valid` to enforce that `min_withdraw_amount` is large enough to prevent this gap:

```rust
require!(
    self.min_withdraw_amount
        >= self.withdraw_bridge_fee.fee_min
            + self.max_btc_gas_fee
            + self.min_change_amount,
    "min_withdraw_amount too small relative to fee_min + max_btc_gas_fee + min_change_amount"
);
``` [3](#0-2) 

### Proof of Concept
Assume the following configuration (all values in satoshis):
- `min_withdraw_amount = 10_000`
- `withdraw_bridge_fee.fee_min = 8_000`, `fee_rate = 10` (0.1%)
- `min_btc_gas_fee = 1_000`, `max_btc_gas_fee = 5_000`
- `min_change_amount = 2_000`

A user initiates a withdrawal with `amount = 10_000` and constructs a PSBT with `gas_fee = 1_000`:

1. `withdraw_fee = max(10_000 * 10 / 10_000, 8_000) = max(10, 8_000) = 8_000`
2. `max_received_amount = 10_000 - 8_000 - 1_000 = 1_000`
3. `min_received_amount = 1_000 - 2_000` → **integer underflow → panic**

The `ft_on_transfer` call reverts. The user's nBTC is returned, but the withdrawal is blocked. The user cannot withdraw at the minimum allowed amount. [5](#0-4)

### Citations

**File:** contracts/satoshi-bridge/src/psbt.rs (L238-251)
```rust
        let gas_fee = total_input_amount - total_output_amount;
        // When constructing the withdraw transaction, if the change is less than min_change_amount (dust),
        // the caller may deduct a portion from the user's output to make the change amount meet min_change_amount.
        // Therefore, the contract relaxes the validation.
        let max_received_amount = amount - withdraw_fee - gas_fee;
        let min_received_amount = max_received_amount - config.min_change_amount;
        require!(
            actual_received_amount >= min_received_amount
                && actual_received_amount <= max_received_amount,
            format!(
                "The user's output amount ({}) is out of the valid range ({}, {})",
                actual_received_amount, min_received_amount, max_received_amount
            )
        );
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

**File:** contracts/satoshi-bridge/src/config.rs (L123-158)
```rust
impl Config {
    pub fn assert_valid(&self) {
        let confirmations_valid_range = 2..=100;
        require!(
            self.confirmations_strategy
                .values()
                .all(|v| confirmations_valid_range.contains(v)),
            "Invalid confirmations_strategy"
        );
        self.deposit_bridge_fee.assert_valid();
        self.withdraw_bridge_fee.assert_valid();
        require!(
            self.min_change_amount < self.max_change_amount,
            "min_change_amount must be less than max_change_amount"
        );
        require!(
            self.min_btc_gas_fee < self.max_btc_gas_fee,
            "min_btc_gas_fee must be less than max_btc_gas_fee"
        );
        require!(
            self.active_management_lower_limit < self.active_management_upper_limit,
            "active_management_lower_limit must be less than active_management_upper_limit"
        );
        require!(
            self.passive_management_lower_limit < self.passive_management_upper_limit,
            "passive_management_lower_limit must be less than passive_management_upper_limit"
        );
        require!(
            u128::from(self.unhealthy_utxo_amount) > self.min_change_amount,
            "unhealthy_utxo_amount must be greater than min_change_amount"
        );
        require!(
            self.refund_timelock_sec <= self.unsafe_refund_timelock_sec,
            "refund_timelock_sec must be <= unsafe_refund_timelock_sec"
        );
    }
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L70-140)
```rust
impl Contract {
    pub(crate) fn create_btc_pending_info(
        &mut self,
        sender_id: AccountId,
        amount: u128,
        target_btc_address: String,
        mut psbt: PsbtWrapper,
        max_gas_fee: Option<U128>,
    ) {
        let (utxo_storage_keys, vutxos) = self.generate_vutxos(&mut psbt);
        let max_pending = self.get_max_pending_sign_txs(&sender_id);
        let account = self.internal_unwrap_or_create_mut_account(&sender_id);
        require!(
            account.pending_sign_count() < max_pending,
            "Too many pending sign transactions"
        );

        let withdraw_change_address_script_pubkey =
            self.internal_config().get_change_script_pubkey();
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

        let need_signature_num = psbt.get_input_num();
        let psbt_hex = psbt.serialize();
        let btc_pending_id = psbt.get_pending_id();
        let btc_pending_info = BTCPendingInfo {
            account_id: sender_id.clone(),
            btc_pending_id: btc_pending_id.clone(),
            transfer_amount: amount,
            actual_received_amount,
            withdraw_fee,
            gas_fee,
            burn_amount: actual_received_amount + gas_fee,
            psbt_hex,
            vutxos,
            signatures: vec![None; need_signature_num],
            tx_bytes_with_sign: None,
            create_time_sec: nano_to_sec(env::block_timestamp()),
            last_sign_time_sec: 0,
            state: PendingInfoState::WithdrawOriginal(OriginalState {
                stage: PendingInfoStage::PendingSign,
                max_gas_fee: gas_fee,
                last_rbf_time_sec: None,
                cancel_rbf_reserved: None,
            }),
        };
        require!(
            self.data_mut()
                .btc_pending_infos
                .insert(btc_pending_id.clone(), btc_pending_info.into())
                .is_none(),
            "pending info already exist"
        );
        self.internal_unwrap_mut_account(&sender_id)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());
        Event::UtxoRemoved { utxo_storage_keys }.emit();
        Event::GenerateBtcPendingInfo {
            account_id: &sender_id,
            btc_pending_id: &btc_pending_id,
        }
        .emit();
    }
```
