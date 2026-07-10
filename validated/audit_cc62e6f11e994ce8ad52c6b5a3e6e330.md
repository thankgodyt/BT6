### Title
RBF Withdraw Bypasses Passive UTXO Management Policy — (`contracts/satoshi-bridge/src/rbf/withdraw.rs`)

### Summary

`check_withdraw_rbf_psbt_valid` calls `check_withdraw_psbt` directly instead of `check_withdraw_psbt_valid`, omitting the passive UTXO management policy guards. Any user with a pending withdrawal can submit an RBF PSBT that violates the `input_num` vs `change_num` ratio enforced for original withdrawals, leaving the bridge UTXO pool in a configuration that contradicts the protocol's passive management invariant.

---

### Finding Description

`check_withdraw_psbt_valid` (the validator used for original withdrawals) calls `check_withdraw_psbt` and then applies three additional guards: [1](#0-0) 

```
change_num <= config.max_change_number
input_num  <= config.max_withdrawal_input_number
if utxo_num < passive_management_lower_limit  → require input_num < change_num
if utxo_num > passive_management_upper_limit  → require input_num > change_num
```

`check_withdraw_rbf_psbt_valid` skips all three and calls `check_withdraw_psbt` directly: [2](#0-1) 

`internal_withdraw_rbf` (called from the public `withdraw_rbf` entry point) invokes only `check_withdraw_rbf_psbt_valid`: [3](#0-2) 

The public entry point `withdraw_rbf` carries no role restriction — only `#[pause]` — so any user who owns a pending withdrawal can reach this path: [4](#0-3) 

The RBF PSBT is constructed via `generate_psbt_from_original_psbt_and_new_output`, which preserves the original inputs but accepts a fully user-controlled `output: Vec<TxOut>`: [5](#0-4) 

Because inputs are fixed from the original PSBT, `input_num` is unchanged. However, `change_num` is entirely determined by the user-supplied outputs. The user can therefore freely choose a `change_num` that violates the passive management ratio that was enforced on the original transaction.

---

### Impact Explanation

**Passive management lower-limit scenario** (`utxo_num < passive_management_lower_limit`): the original withdrawal was accepted only because `input_num < change_num` (UTXO-splitting). The RBF can replace it with `input_num >= change_num` (consolidating or neutral). When the RBF confirms on Bitcoin, the bridge receives fewer change UTXOs than the policy mandated, leaving the pool more depleted than intended.

**Passive management upper-limit scenario** (`utxo_num > passive_management_upper_limit`): the original withdrawal required `input_num > change_num` (UTXO-consolidating). The RBF can supply `input_num <= change_num`, returning more UTXOs than intended and keeping the pool bloated.

Additionally, `max_change_number` is not enforced on the RBF, so the user can supply more change outputs than the protocol allows, creating an oversized Bitcoin transaction.

The net effect is that the bridge UTXO pool is left in a configuration that the passive management policy was specifically designed to prevent, potentially degrading the bridge's ability to service future withdrawals when the pool is already under stress.

---

### Likelihood Explanation

The path is fully reachable by any user who has initiated a withdrawal. No privileged role is required. The only precondition is that the bridge is in a passive-management-triggered state (`utxo_num` outside the `[passive_management_lower_limit, passive_management_upper_limit]` band), which is a normal operational condition the policy is designed to handle. The attacker simply submits a `withdraw_rbf` call with outputs that produce a `change_num` violating the ratio.

---

### Recommendation

Replace the direct `check_withdraw_psbt` call inside `check_withdraw_rbf_psbt_valid` with a call to `check_withdraw_psbt_valid` (passing the RBF PSBT's `vutxos` for the `utxo_num` calculation), or extract the three additional guards into a shared helper and call it from both `check_withdraw_psbt_valid` and `check_withdraw_rbf_psbt_valid`. [6](#0-5) 

---

### Proof of Concept

1. Bridge state: `utxo_num < passive_management_lower_limit`.
2. User initiates a withdrawal. `check_withdraw_psbt_valid` enforces `input_num < change_num`; the original PSBT is accepted with, e.g., 1 input and 2 change outputs.
3. User calls `withdraw_rbf` with a new `output` containing only 1 change output (making `change_num = 1`, so `input_num == change_num`).
4. `check_withdraw_rbf_psbt_valid` → `check_withdraw_psbt`: validates amounts, gas fee, and output addresses — all pass. The passive management guard (`require input_num < change_num`) is never reached.
5. The RBF PSBT is accepted, signed by MPC, and broadcast. When confirmed, the bridge receives 1 change UTXO instead of 2, worsening the already-depleted pool contrary to the protocol's passive management intent.

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

**File:** contracts/satoshi-bridge/src/rbf/withdraw.rs (L23-30)
```rust
        let (_, _, actual_received_amount, gas_fee) = self.check_withdraw_psbt(
            withdraw_rbf_psbt,
            target_address,
            &withdraw_change_address_script_pubkey,
            &original_tx_btc_pending_info.vutxos,
            original_tx_btc_pending_info.transfer_amount,
            original_tx_btc_pending_info.withdraw_fee,
        );
```

**File:** contracts/satoshi-bridge/src/rbf/withdraw.rs (L57-58)
```rust
        let (actual_received_amount, gas_fee) =
            self.check_withdraw_rbf_psbt_valid(original_tx_btc_pending_info, &withdraw_rbf_psbt);
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L258-274)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn withdraw_rbf(
        &mut self,
        original_btc_pending_verify_id: String,
        output: Vec<TxOut>,
        chain_specific_data: Option<ChainSpecificData>,
    ) {
        let account_id = env::predecessor_account_id();
        self.require_pending_sign_capacity(&account_id);

        self.withdraw_rbf_chain_specific(
            account_id,
            original_btc_pending_verify_id,
            output,
            chain_specific_data,
        );
    }
```

**File:** contracts/satoshi-bridge/src/bitcoin_utils/contract_methods.rs (L110-117)
```rust
    pub(crate) fn generate_psbt_from_original_psbt_and_new_output(
        &self,
        original_tx_btc_pending_info: &BTCPendingInfo,
        output: Vec<TxOut>,
    ) -> PsbtWrapper {
        let original_psbt = original_tx_btc_pending_info.get_psbt();
        PsbtWrapper::from_original_psbt(original_psbt, output)
    }
```
