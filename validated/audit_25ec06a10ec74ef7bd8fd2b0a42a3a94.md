### Title
Unsigned Arithmetic Underflow in `check_withdraw_psbt` Before Gas-Fee Bounds Validation Causes Panic-Driven Withdrawal Fault - (File: contracts/satoshi-bridge/src/psbt.rs)

### Summary
`check_withdraw_psbt` performs three unsigned `u128` subtractions before the gas-fee bounds check. With `overflow-checks = true` enabled, any subtraction where the subtrahend exceeds the minuend panics at runtime. A user can trigger this by submitting a PSBT whose total output amount exceeds the total input amount, or by operating under a configuration where `min_withdraw_amount < max_btc_gas_fee + withdraw_fee`.

### Finding Description
In `check_withdraw_psbt`, the following unsigned subtractions occur in sequence:

```rust
// psbt.rs line 238
let gas_fee = total_input_amount - total_output_amount;

// psbt.rs line 242
let max_received_amount = amount - withdraw_fee - gas_fee;

// psbt.rs line 243
let min_received_amount = max_received_amount - config.min_change_amount;
```

The gas-fee bounds check (`require!(gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee, ...)`) appears at lines 252–258, **after** all three arithmetic operations. This ordering creates two distinct underflow paths:

**Path 1 — Line 238:** A user submits a `TokenReceiverMessage::Withdraw` PSBT where the sum of outputs exceeds the sum of the selected UTXOs' values. Individual output validations (each change output `>= min_change_amount`) do not prevent the total from exceeding the total input. No prior guard checks `total_output_amount <= total_input_amount` before the subtraction.

**Path 2 — Line 242:** If the deployed configuration satisfies `min_withdraw_amount < max_btc_gas_fee + withdraw_fee`, a user withdrawing exactly `min_withdraw_amount` with a gas fee at `max_btc_gas_fee` causes a panic here, even though both `amount` and `gas_fee` are individually within their valid ranges. `Config::assert_valid()` does **not** enforce `min_withdraw_amount >= max_btc_gas_fee + withdraw_fee_max`.

The vulnerable function is called from:
- `check_withdraw_psbt_valid` → `create_btc_pending_info` → `ft_on_transfer_withdraw_chain_specific` → `ft_on_transfer` (public withdrawal entry point)
- `check_withdraw_rbf_psbt_valid` → `internal_withdraw_rbf` → `withdraw_rbf` (user-callable RBF) [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Impact Explanation
With `overflow-checks = true` (CLAUDE.md line 68), these unsigned subtractions panic rather than wrap silently. In NEAR, a panic in `ft_on_transfer` causes the receipt to fail; NEAR's state rollback restores any mutated state (including UTXOs removed by `generate_vutxos` before the validation), and the NEP-141 `ft_resolve_transfer` callback refunds the user's tokens. There is no permanent fund loss or stuck state.

The impact is a publicly reachable panic-driven fault in the production withdrawal path: the withdrawal fails with a runtime arithmetic panic instead of a proper `require!` error. This matches the Low allowed impact: **"Publicly reachable panic-driven fault in production bridge/token paths without direct theft."** [5](#0-4) 

### Likelihood Explanation
Any NEAR account holding nBTC can trigger the panic at line 238 by constructing a `TokenReceiverMessage::Withdraw` whose output vector sums to more than the selected UTXO's value. The panic at line 242 is reachable whenever the deployed config satisfies `min_withdraw_amount < max_btc_gas_fee + withdraw_fee`, a relationship the config validation does not prevent. The unit-test default config (`min_withdraw_amount = 70000`, `max_btc_gas_fee = 50000`, `withdraw_bridge_fee.fee_min = 50000`) already satisfies this condition (`70000 < 100000`). [6](#0-5) 

### Recommendation
Reorder the validation: guard against underflow with explicit `require!` checks before performing the arithmetic, and move the gas-fee bounds check before computing `max_received_amount`:

```rust
require!(
    total_output_amount <= total_input_amount,
    "Outputs exceed inputs"
);
let gas_fee = total_input_amount - total_output_amount;
require!(
    gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
    format!("Invalid gas fee ({}). valid range: [{}, {}].", gas_fee, config.min_btc_gas_fee, config.max_btc_gas_fee)
);
require!(
    amount >= withdraw_fee + gas_fee,
    "Amount too small to cover fees and gas"
);
let max_received_amount = amount - withdraw_fee - gas_fee;
require!(
    max_received_amount >= config.min_change_amount,
    "Received amount too small"
);
let min_received_amount = max_received_amount - config.min_change_amount;
```

Additionally, add an invariant to `Config::assert_valid()` enforcing `min_withdraw_amount >= max_btc_gas_fee + withdraw_fee_min` to prevent misconfiguration from enabling the line-242 path. [7](#0-6) [8](#0-7) 

### Proof of Concept
1. Alice holds nBTC and calls `ft_transfer_call` on the nBTC contract with `amount = min_withdraw_amount` and a `TokenReceiverMessage::Withdraw` message selecting a UTXO of value V and specifying outputs that sum to `V + 1`.
2. The bridge's `ft_on_transfer` → `create_btc_pending_info` → `check_withdraw_psbt_valid` → `check_withdraw_psbt` reaches line 238.
3. `total_input_amount = V`, `total_output_amount = V + 1`; the subtraction `V - (V+1)` panics with an arithmetic overflow.
4. The receipt fails; NEAR rolls back all state changes (UTXOs restored); `ft_resolve_transfer` refunds Alice's tokens.
5. The withdrawal is blocked with a cryptic panic instead of a proper validation error.

For the line-242 path: with the default config, Alice withdraws exactly `70000` satoshis and constructs a PSBT where `gas_fee = 50000` (within `[10000, 50000]`). `amount - withdraw_fee - gas_fee = 70000 - 50000 - 50000` underflows and panics before the gas-fee bounds check at line 252 can execute. [1](#0-0) [9](#0-8)

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

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L29-67)
```rust
        let amount = amount.into();
        require!(
            amount >= self.internal_config().min_withdraw_amount,
            "Invalid amount"
        );
        let message = serde_json::from_str::<TokenReceiverMessage>(&msg).expect("INVALID MSG");
        let token_id = env::predecessor_account_id();
        require!(
            token_id == self.internal_config().nbtc_account_id,
            "Invalid token_id"
        );
        match message {
            TokenReceiverMessage::DepositProtocolFee => {
                self.data_mut().acc_collected_protocol_fee += amount;
                self.data_mut().cur_available_protocol_fee += amount;
                Event::DepositProtocolFee {
                    account_id: &sender_id,
                    amount: U128(amount),
                }
                .emit();
                PromiseOrValue::Value(U128(0))
            }
            TokenReceiverMessage::Withdraw {
                target_btc_address,
                input,
                output,
                max_gas_fee,
                chain_specific_data,
            } => self.ft_on_transfer_withdraw_chain_specific(
                sender_id,
                amount,
                target_btc_address,
                input,
                output,
                max_gas_fee,
                chain_specific_data,
            ),
        }
    }
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L71-98)
```rust
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

**File:** contracts/satoshi-bridge/src/unit/mod.rs (L63-68)
```rust
        min_deposit_amount: 20000,
        min_withdraw_amount: 70000,
        min_change_amount: 0,
        max_change_amount: u128::MAX,
        min_btc_gas_fee: 10000,
        max_btc_gas_fee: 50000,
```
