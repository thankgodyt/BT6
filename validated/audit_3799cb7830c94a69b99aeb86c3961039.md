### Title
Hard `max_btc_gas_fee` Bound Disables All Withdrawals When Bitcoin Network Fees Spike — (File: `contracts/satoshi-bridge/src/psbt.rs`)

---

### Summary

The `check_withdraw_psbt` function enforces a hard upper bound (`config.max_btc_gas_fee`) on the Bitcoin transaction gas fee. When Bitcoin network fees spike above this configured ceiling, every new withdrawal attempt is rejected by the contract. Users holding nBTC cannot redeem it for BTC until the DAO manually updates the config, creating a stuck bridge state requiring operator intervention.

---

### Finding Description

In `check_withdraw_psbt`, the gas fee is derived from the user-submitted PSBT as `total_input_amount − total_output_amount`, then validated against a fixed range:

```rust
// contracts/satoshi-bridge/src/psbt.rs  lines 252-258
require!(
    gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
    format!(
        "Invalid gas fee ({}). valid range: [{}, {}].",
        gas_fee, config.min_btc_gas_fee, config.max_btc_gas_fee
    )
);
``` [1](#0-0) 

The identical bound is enforced in `check_psbt_output_all_change_address`, which covers active UTXO management:

```rust
// contracts/satoshi-bridge/src/psbt.rs  lines 153-159
require!(
    gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
    ...
);
``` [2](#0-1) 

The call chain for a user withdrawal is:

`ft_on_transfer` → `ft_on_transfer_withdraw_chain_specific` → `create_btc_pending_info` → `check_withdraw_psbt_valid` → `check_withdraw_psbt` [3](#0-2) [4](#0-3) 

`max_btc_gas_fee` is a static field in `Config` that can only be changed by the DAO via `update_config`: [5](#0-4) [6](#0-5) 

When the Bitcoin mempool is congested (e.g., during Ordinals/Runes inscription waves, halving periods, or other demand spikes), the minimum fee rate required for timely confirmation can exceed `max_btc_gas_fee`. At that point:

- Any PSBT with a gas fee high enough to be confirmed on Bitcoin is **rejected by the contract** (`gas_fee > max_btc_gas_fee`).
- Any PSBT with a gas fee accepted by the contract (`gas_fee ≤ max_btc_gas_fee`) will **not be confirmed** by the Bitcoin network.

The result is that the entire withdrawal path is blocked until the DAO reacts and raises the ceiling. The same condition disables active UTXO management, compounding the stuck state.

---

### Impact Explanation

**Medium — stuck bridge state requiring operator intervention.**

All nBTC → BTC withdrawals are disabled for the duration of the fee spike. Users cannot redeem their nBTC. Because `ft_on_transfer` panics on the failed `require!`, the nBTC transfer reverts and user tokens are not permanently lost, but the bridge's core withdrawal functionality is completely non-operational until the DAO manually updates `max_btc_gas_fee`. Active UTXO management is simultaneously disabled via the same check in `check_psbt_output_all_change_address`, preventing the protocol from consolidating or splitting UTXOs during the outage.

---

### Likelihood Explanation

**Medium.** Bitcoin fee spikes above any fixed ceiling are a recurring, documented market event (Ordinals craze 2023, halving 2024, etc.). The `max_btc_gas_fee` is a single static value with no dynamic adjustment mechanism. The DAO must notice the spike, propose and execute a config update, and have it land on-chain — all while the withdrawal path is down. Historical fee spikes have lasted hours to days, making the window of impact material.

---

### Recommendation

1. **Dynamic ceiling**: Replace the hard `max_btc_gas_fee` with a configurable multiplier over a rolling on-chain fee estimate, or allow users to specify `max_gas_fee` that is validated only against a soft advisory limit rather than a hard reject.
2. **Operator fast-path**: Allow a `Role::Operator` (not just DAO) to raise `max_btc_gas_fee` without a governance delay, analogous to how `cancel_withdraw` is available to Operator.
3. **Graceful degradation**: Instead of panicking, return the nBTC to the user with an informative error so the UX is clear, and emit an event so monitoring can alert the DAO immediately.

---

### Proof of Concept

1. Bitcoin mempool congestion drives the minimum economically viable fee rate above `config.max_btc_gas_fee` (e.g., `max_btc_gas_fee = 50_000 sat` but network requires `80_000 sat` for next-block confirmation).
2. User calls `ft_transfer_call` on the nBTC contract with a `Withdraw` message containing a PSBT whose `total_input − total_output = 80_000 sat`.
3. `check_withdraw_psbt` evaluates `80_000 <= 50_000` → `false` → `require!` panics with `"Invalid gas fee (80000). valid range: [1000, 50000]."`.
4. The entire `ft_on_transfer` call reverts; nBTC is returned to the user.
5. User retries with `gas_fee = 50_000 sat` (within bounds); the Bitcoin transaction is broadcast but sits unconfirmed indefinitely because the network demands `80_000 sat`.
6. All withdrawals are effectively frozen until the DAO executes `update_config` with a higher `max_btc_gas_fee`. [7](#0-6) [8](#0-7)

### Citations

**File:** contracts/satoshi-bridge/src/psbt.rs (L10-70)
```rust
    pub fn check_withdraw_psbt_valid(
        &self,
        target_btc_address: String,
        withdraw_change_address_script_pubkey: &ScriptBuf,
        withdraw_psbt: &PsbtWrapper,
        vutxos: &[VUTXO],
        amount: u128,
        withdraw_fee: u128,
        max_gas_fee: Option<U128>,
    ) -> (u128, u128) {
        let config = self.internal_config();
        let vutxos_len = u32::try_from(vutxos.len()).unwrap_or_else(|_| {
            env::panic_str("vutxos len overflow");
        });
        let utxo_num = self.data().utxos.len() + vutxos_len;
        let (input_num, change_num, actual_received_amount, gas_fee) = self.check_withdraw_psbt(
            withdraw_psbt,
            target_btc_address,
            withdraw_change_address_script_pubkey,
            vutxos,
            amount,
            withdraw_fee,
        );

        if let Some(max_gas_fee) = max_gas_fee {
            require!(
                gas_fee <= max_gas_fee.0,
                format!(
                    "Gas fee does not match the provided max fee (gas fee = {}; max gas fee = {})",
                    gas_fee, max_gas_fee.0
                )
            );
        }

        require!(
            change_num <= usize::from(config.max_change_number),
            format!("change_num must not exceed {}", config.max_change_number)
        );
        require!(
            input_num <= usize::from(config.max_withdrawal_input_number),
            format!(
                "input must not exceed {}",
                config.max_withdrawal_input_number
            )
        );

        if utxo_num < config.passive_management_lower_limit {
            require!(input_num < change_num, "require input_num < change_num");
        } else if utxo_num > config.passive_management_upper_limit {
            require!(input_num > change_num, "require input_num > change_num");
        }

        Event::WithdrawBtcDetail {
            cost_nbtc: amount.into(),
            withdraw_fee: withdraw_fee.into(),
            btc_gas_fee: gas_fee.into(),
            actual_received_amount: actual_received_amount.into(),
        }
        .emit();
        (actual_received_amount, gas_fee)
    }
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L153-159)
```rust
            require!(
                gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
                format!(
                    "Invalid gas fee ({}). valid range: [{}, {}].",
                    gas_fee, config.min_btc_gas_fee, config.max_btc_gas_fee
                )
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

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L51-66)
```rust
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
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L90-98)
```rust
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

**File:** contracts/satoshi-bridge/src/config.rs (L83-88)
```rust
    #[serde(with = "u128_dec_format")]
    pub min_btc_gas_fee: u128,
    // The max gas fee applicable for Bitcoin transactions
    #[serde(with = "u128_dec_format")]
    pub max_btc_gas_fee: u128,
    // The maximum number of inputs that can be used for a Withdraw.
```

**File:** contracts/satoshi-bridge/src/config.rs (L266-301)
```rust
    pub fn apply(self, config: &mut Config) {
        macro_rules! set_if_some {
            ($field:ident) => {
                if let Some(v) = self.$field {
                    config.$field = v;
                }
            };
        }
        set_if_some!(btc_light_client_account_id);
        set_if_some!(nbtc_account_id);
        set_if_some!(confirmations_delta);
        set_if_some!(extra_msg_confirmations_delta);
        set_if_some!(deposit_bridge_fee);
        set_if_some!(withdraw_bridge_fee);
        set_if_some!(min_deposit_amount);
        set_if_some!(min_withdraw_amount);
        set_if_some!(min_change_amount);
        set_if_some!(max_change_amount);
        set_if_some!(min_btc_gas_fee);
        set_if_some!(max_btc_gas_fee);
        set_if_some!(max_withdrawal_input_number);
        set_if_some!(max_change_number);
        set_if_some!(max_active_utxo_management_input_number);
        set_if_some!(max_active_utxo_management_output_number);
        set_if_some!(active_management_lower_limit);
        set_if_some!(active_management_upper_limit);
        set_if_some!(passive_management_lower_limit);
        set_if_some!(passive_management_upper_limit);
        set_if_some!(rbf_num_limit);
        set_if_some!(max_btc_tx_pending_sec);
        set_if_some!(unhealthy_utxo_amount);
        set_if_some!(refund_timelock_sec);
        set_if_some!(unsafe_refund_timelock_sec);

        config.assert_valid();
    }
```
