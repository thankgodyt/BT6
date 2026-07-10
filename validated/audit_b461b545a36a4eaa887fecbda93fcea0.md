### Title
Unchecked Arithmetic Subtractions in `check_withdraw_psbt` Panic Before Gas-Fee Validation - (File: contracts/satoshi-bridge/src/psbt.rs)

### Summary
`check_withdraw_psbt` in `psbt.rs` performs three consecutive unchecked u128 subtractions before the gas-fee range check is reached. With `overflow-checks = true`, any underflow panics the transaction. A user can trigger these panics through a crafted withdrawal PSBT, causing the withdrawal to abort with an opaque panic rather than a clean validation error.

### Finding Description
In `check_withdraw_psbt` (lines 238–258), the following unchecked subtractions appear in order:

```rust
// line 238 – panics if total_output_amount > total_input_amount
let gas_fee = total_input_amount - total_output_amount;

// line 242 – panics if withdraw_fee + gas_fee > amount
let max_received_amount = amount - withdraw_fee - gas_fee;

// line 243 – panics if max_received_amount < config.min_change_amount
let min_received_amount = max_received_amount - config.min_change_amount;
```

The gas-fee range check (`gas_fee >= min_btc_gas_fee && gas_fee <= max_btc_gas_fee`) only appears at lines 252–258, **after** all three potentially underflowing subtractions. This ordering means:

- **Path A (line 238):** A user submits a PSBT whose output values sum to more than the selected UTXO inputs. `total_output_amount > total_input_amount` → immediate panic before any validation.
- **Path B (line 243):** A user submits a PSBT with a gas fee near `max_btc_gas_fee` while withdrawing near `min_withdraw_amount`. If `amount − withdraw_fee − gas_fee < config.min_change_amount`, line 243 panics before the gas-fee check at line 252 is ever reached.

`Config::assert_valid` does not enforce the relationship `min_withdraw_amount − max_bridge_fee − max_btc_gas_fee ≥ min_change_amount`, so Path B is reachable with a valid configuration.

By contrast, `refund.rs` line 282 correctly uses `checked_sub` for the analogous refund-amount calculation, showing the inconsistency is unintentional. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation
When the panic fires inside `ft_on_transfer`, the entire NEAR transaction reverts. The NEP-141 `ft_transfer_call` mechanism on the nBTC contract then refunds the user's tokens. No funds are permanently lost and no bridge state is durably mutated. The harm is a publicly reachable, opaque panic-driven abort in the production withdrawal path instead of a clean, descriptive error — matching the **Low** allowed impact: *"Publicly reachable invariant-violation, stuck-state, or panic-driven fault in production bridge/token paths without direct theft."* [4](#0-3) 

### Likelihood Explanation
- **Path A** is trivially reachable: any user can craft a PSBT whose output sum exceeds the input sum.
- **Path B** is reachable whenever the deployed configuration satisfies `min_withdraw_amount − fee(min_withdraw_amount) − max_btc_gas_fee < min_change_amount`. `Config::assert_valid` does not guard against this relationship. [5](#0-4) 

### Recommendation
Replace the three unchecked subtractions with `checked_sub` / `saturating_sub` and emit descriptive errors. Also move the gas-fee range check to **before** the `max_received_amount` / `min_received_amount` calculations so that an out-of-range gas fee is rejected cleanly rather than causing a downstream underflow:

```rust
// 1. Validate gas fee first
let gas_fee = total_input_amount
    .checked_sub(total_output_amount)
    .unwrap_or_else(|| env::panic_str("Output amount exceeds input amount"));
require!(
    gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
    format!("Invalid gas fee ({}). valid range: [{}, {}].",
            gas_fee, config.min_btc_gas_fee, config.max_btc_gas_fee)
);

// 2. Then compute the received-amount bounds safely
let max_received_amount = amount
    .checked_sub(withdraw_fee)
    .and_then(|v| v.checked_sub(gas_fee))
    .unwrap_or_else(|| env::panic_str("Amount insufficient to cover fees and gas"));
let min_received_amount = max_received_amount.saturating_sub(config.min_change_amount);
```

Additionally, add a validation in `Config::assert_valid` that `min_withdraw_amount` is large enough to cover `max_btc_gas_fee + fee_min + min_change_amount`.

### Proof of Concept

**Path A – line 238 panic:**
1. User calls `ft_transfer_call` on nBTC with any `amount` and a PSBT where the outputs sum to `total_input_amount + 1`.
2. `gas_fee = total_input_amount − (total_input_amount + 1)` underflows → panic.
3. Transaction reverts; nBTC is refunded.

**Path B – line 243 panic:**
1. Assume config: `min_withdraw_amount = 100_000`, `max_btc_gas_fee = 60_000`, `fee_min = 1_000`, `min_change_amount = 50_000`.
2. User calls `ft_transfer_call` with `amount = 100_000` and a PSBT where `gas_fee = 60_000`.
3. `max_received_amount = 100_000 − 1_000 − 60_000 = 39_000`.
4. `min_received_amount = 39_000 − 50_000` → underflow → panic at line 243, before the gas-fee check at line 252.
5. Transaction reverts; nBTC is refunded. [6](#0-5)

### Citations

**File:** contracts/satoshi-bridge/src/psbt.rs (L164-262)
```rust
    pub fn check_withdraw_psbt(
        &self,
        psbt: &PsbtWrapper,
        target_btc_address: String,
        withdraw_change_address_script_pubkey: &ScriptBuf,
        vutxos: &[VUTXO],
        amount: u128,
        withdraw_fee: u128,
    ) -> (usize, usize, u128, u128) {
        let config = self.internal_config();
        let (min_input_amount, total_input_amount) = vutxos
            .iter()
            .map(|vutxo| u128::from(vutxo.get_amount()))
            .fold((u128::MAX, 0u128), |(min, sum), v| (min.min(v), sum + v));
        let mut total_output_amount = 0;
        let mut actual_received_amounts = vec![];
        let mut change_amounts = vec![];
        let signer_is_unrestricted =
            self.acl_has_role(Role::UnrestrictedRelayer.into(), env::signer_account_id());

        if !psbt.get_output().is_empty() {
            // `None` when the target is a shielded-only Zcash unified address (no transparent
            // receiver): the user is paid via the Orchard bundle and every transparent output
            // is change, so there is nothing for a transparent output to match against.
            let target_address_script_pubkey = self
                .internal_config()
                .target_script_pubkey(&target_btc_address);

            psbt.get_output().iter().for_each(|output| {
                let output_value = output.value.to_sat() as u128;
                total_output_amount += output_value;
                if target_address_script_pubkey.as_ref() == Some(&output.script_pubkey) {
                    actual_received_amounts.push(output_value);
                } else if &output.script_pubkey == withdraw_change_address_script_pubkey {
                    require!(
                        output_value >= config.min_change_amount,
                        "The change amount is too small"
                    );
                    require!(
                        signer_is_unrestricted || output_value < min_input_amount,
                        "The change amount must be less than the smallest input, or the caller must have the UnrestrictedRelayer role"
                    );
                    change_amounts.push(output_value);
                } else {
                    let output_address =
                        Address::from_script(&output.script_pubkey, config.chain.clone())
                            .expect("Unsupported btc address type");
                    env::panic_str(
                        format!("Invalid transaction output address: {}", output_address).as_str(),
                    );
                }
            });
        }

        total_output_amount += psbt.add_extra_outputs(&mut actual_received_amounts);

        require!(
            actual_received_amounts.len() == 1,
            "only one user output is allowed."
        );
        let actual_received_amount = actual_received_amounts[0];
        let input_num = psbt.get_input_num();
        let change_num = change_amounts.len();
        if input_num > change_num {
            require!(
                change_amounts
                    .into_iter()
                    .all(|v| v < config.max_change_amount),
                format!(
                    "Any change amount should be less than {} when input_num > change_num",
                    config.max_change_amount
                )
            );
        }
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
        require!(
            gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
            format!(
                "Invalid gas fee ({}). valid range: [{}, {}].",
                gas_fee, config.min_btc_gas_fee, config.max_btc_gas_fee
            )
        );

        self.check_psbt_chain_specific(psbt, gas_fee, target_btc_address);
        (input_num, change_num, actual_received_amount, gas_fee)
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L280-284)
```rust
        let refund_amount = refund_request
            .amount
            .checked_sub(refund_request.gas_fee)
            .expect("Deposit amount too small to cover gas fee");
        require!(refund_amount > 0, "Refund amount is zero after gas fee");
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
