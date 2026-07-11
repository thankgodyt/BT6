### Title
Passive UTXO Management Constraint Enforced Unconditionally Blocks All Withdrawals When UTXO Count Falls Below Lower Limit — (File: `contracts/satoshi-bridge/src/psbt.rs`)

---

### Summary

In `check_withdraw_psbt_valid`, when the bridge's UTXO count falls below `passive_management_lower_limit`, the contract unconditionally enforces `input_num < change_num`. When a withdrawal produces zero or insufficient change outputs — a valid and common scenario — this constraint is mathematically impossible to satisfy, permanently blocking all such withdrawals until operator intervention restores the UTXO count.

---

### Finding Description

`check_withdraw_psbt_valid` in `psbt.rs` applies passive UTXO management policy to every withdrawal PSBT:

```rust
if utxo_num < config.passive_management_lower_limit {
    require!(input_num < change_num, "require input_num < change_num");
} else if utxo_num > config.passive_management_upper_limit {
    require!(input_num > change_num, "require input_num > change_num");
}
```

The intent is to use withdrawals as an opportunity to split UTXOs when the pool is depleted. However, the constraint is enforced unconditionally, without checking whether it is satisfiable given the other enforced limits.

**Edge case 1 — zero change outputs (`change_num == 0`):**
A user withdrawing the exact value of a UTXO (gas fee absorbed from the user output) produces no change output. Here `change_num = 0`, so the constraint becomes `input_num < 0`, which is impossible since `input_num ≥ 1` always.

**Edge case 2 — `max_change_number` caps satisfiability:**
Even when the user attempts to include change outputs, the separately enforced limit applies:

```rust
require!(
    change_num <= usize::from(config.max_change_number),
    format!("change_num must not exceed {}", config.max_change_number)
);
```

When `max_change_number == 1` (a natural default for a single-change-output policy) and `input_num == 1`, the constraint `input_num < change_num` requires `1 < change_num`, i.e., `change_num ≥ 2`. But `change_num ≤ max_change_number = 1` — a direct contradiction. No valid PSBT can be constructed.

More generally, whenever `max_change_number ≤ input_num`, the constraint `input_num < change_num` is unsatisfiable for any PSBT the user can submit.

This is structurally identical to the EraVM `mul/div` bug: a relation is enforced even in the edge case where it cannot hold, making the operation permanently fail rather than skipping the inapplicable constraint.

---

### Impact Explanation

When `utxo_num < passive_management_lower_limit` and `max_change_number ≤ input_num`, every withdrawal attempt panics at the `require!` check. The bridge enters a state where no user can complete a withdrawal. Users' nBTC is either returned (if validation occurs inside `ft_on_transfer`) or stuck in the bridge (if validation occurs in a subsequent call after the bridge has already held the tokens). Either way, the bridge's withdrawal path is completely blocked until an operator uses `active_utxo_management` to split UTXOs and raise the count above `passive_management_lower_limit`. This constitutes a stuck bridge state requiring operator intervention.

**Impact class:** Medium — stuck bridge state requiring operator intervention.

---

### Likelihood Explanation

The bridge's UTXO count naturally decreases as withdrawals are processed (each withdrawal spends inputs and may produce fewer change outputs than inputs consumed). Reaching `utxo_num < passive_management_lower_limit` is an expected operational condition — it is precisely the condition the passive management policy is designed to handle. Once reached, the policy itself becomes the blocker. With `max_change_number` set to 1 (a common single-change-output configuration), the constraint is unsatisfiable for every single-input withdrawal, meaning the entire withdrawal path is blocked for all users simultaneously.

---

### Recommendation

Do not enforce the passive management constraint when it is mathematically unsatisfiable. Specifically, skip the `input_num < change_num` requirement when `change_num == 0`, or more generally when `max_change_number ≤ input_num`. The corrected guard should be:

```rust
if utxo_num < config.passive_management_lower_limit {
    // Only enforce if the user can actually satisfy the constraint
    if change_num > 0 {
        require!(input_num < change_num, "require input_num < change_num");
    }
    // else: no change output — constraint is inapplicable, allow the withdrawal
}
```

Alternatively, decouple passive UTXO management from user withdrawals entirely and rely solely on `active_utxo_management` (operator-controlled) to rebalance the UTXO pool.

---

### Proof of Concept

1. Bridge is configured with `passive_management_lower_limit = 10`, `max_change_number = 1`.
2. Through normal withdrawal activity, `utxo_num` drops to 8 (below the lower limit).
3. User holds nBTC and initiates a withdrawal spending 1 UTXO with no change output (`change_num = 0`).
4. `check_withdraw_psbt_valid` is called: `utxo_num (8) < passive_management_lower_limit (10)` → constraint `input_num < change_num` is enforced → `1 < 0` → `require!` panics.
5. User retries with 1 change output (`change_num = 1`): `1 < 1` → still panics.
6. User cannot include 2 change outputs because `max_change_number = 1`.
7. No valid PSBT exists. All withdrawals are blocked until an operator calls `active_utxo_management` to split UTXOs and raise `utxo_num` above 10.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2)

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
