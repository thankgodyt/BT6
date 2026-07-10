The code is fully readable. Let me trace the exact path.

**Key facts from the code:**

**`check_withdraw_psbt` (lines 227–237):** The `max_change_amount` check is guarded by `if input_num > change_num`. When `input_num <= change_num`, the block is skipped entirely. [1](#0-0) 

**Per-output check (lines 202–205):** For an unprivileged relayer, each change output must satisfy `output_value < min_input_amount` (the smallest input UTXO). There is no `max_change_amount` check here. [2](#0-1) 

**Passive management gate (lines 56–60):** When `utxo_num` is between `passive_management_lower_limit` and `passive_management_upper_limit`, no constraint is placed on `input_num` vs `change_num`, so `input_num <= change_num` is freely allowed. [3](#0-2) 

**The bypass is real:** If a bridge UTXO has value > `max_change_amount` (e.g., a 5 BTC UTXO with `max_change_amount` = 1 BTC), an unprivileged relayer can submit a PSBT with 1 input and 2 change outputs (`input_num=1 <= change_num=2`). A change output of 1.5 BTC satisfies `output_value < min_input_amount` (5 BTC) but violates `max_change_amount` (1 BTC). Because `input_num <= change_num`, the `max_change_amount` block is never entered.

**Impact ceiling:** The oversized change UTXO goes to the bridge's own change address — no funds are redirected or stolen. Active management output validation (`check_psbt_output_all_change_address` with `force_healthy_output=true`) enforces `<= max_change_amount` on outputs, not inputs, so the oversized UTXO can still be consumed as an input in a future active-management transaction to split it. [4](#0-3) 

The result is a policy invariant violation — an oversized UTXO in the bridge pool — but no permanent locking, no theft, and no unauthorized minting. The UTXO remains spendable by the bridge.

---

### Title
Conditional `max_change_amount` bypass when `input_num <= change_num` in `check_withdraw_psbt` — (`contracts/satoshi-bridge/src/psbt.rs`)

### Summary
The `max_change_amount` guard in `check_withdraw_psbt` is only enforced when `input_num > change_num`. An unprivileged relayer can submit a withdrawal PSBT with `input_num <= change_num` and include a change output whose value exceeds `max_change_amount`, bypassing the limit entirely.

### Finding Description
In `check_withdraw_psbt` (lines 227–237), the check that all change outputs are below `config.max_change_amount` is wrapped in `if input_num > change_num { … }`. When `input_num <= change_num`, the block is skipped. The only per-output constraint that still applies to an unprivileged relayer is `output_value < min_input_amount` (line 203). If any input UTXO has value greater than `max_change_amount`, a change output can be constructed in the range `[max_change_amount, min_input_amount)`, which passes all checks while violating the intended invariant.

The passive management gate in `check_withdraw_psbt_valid` (lines 56–60) imposes no constraint on `input_num` vs `change_num` when `utxo_num` is between the two limits, so the attacker-chosen ratio is freely accepted.

### Impact Explanation
The oversized change UTXO is deposited into the bridge's own UTXO pool (bridge change address). No funds are redirected to the attacker. The UTXO can still be consumed as an input in future active-management or withdrawal transactions. The concrete harm is a policy invariant violation: the bridge's UTXO pool contains a UTXO that exceeds `max_change_amount`, which cannot be produced as an output in active management (`force_healthy_output` path), potentially complicating automated UTXO management and requiring operator attention to rebalance. No direct theft, unauthorized minting, or permanent fund lock occurs.

**Severity: Low** — publicly reachable invariant violation in a production bridge path, no direct theft.

### Likelihood Explanation
Reachable by any user who initiates a withdrawal (`ft_on_transfer` → `create_btc_pending_info`) when the bridge holds at least one UTXO with value > `max_change_amount` and `utxo_num` is within the passive management window. Both conditions are plausible in normal bridge operation.

### Recommendation
Remove the `if input_num > change_num` condition and enforce `max_change_amount` unconditionally for all change outputs in `check_withdraw_psbt`:

```rust
// Before (conditional):
if input_num > change_num {
    require!(change_amounts.into_iter().all(|v| v < config.max_change_amount), ...);
}

// After (unconditional):
require!(change_amounts.iter().all(|v| *v < config.max_change_amount), ...);
```

### Proof of Concept
Preconditions:
- `utxo_num` is between `passive_management_lower_limit` and `passive_management_upper_limit`
- Bridge holds a UTXO of value `V` where `V > max_change_amount` (e.g., `V = 5_000_000 sat`, `max_change_amount = 1_000_000 sat`)

Attack:
1. Relayer calls `ft_on_transfer` with a withdrawal message containing a PSBT:
   - 1 input: the 5 BTC UTXO
   - 1 user output: valid withdrawal amount
   - 2 change outputs: one at `1_500_000 sat` (> `max_change_amount`, < `min_input_amount = 5_000_000`)
2. `check_withdraw_psbt` is called. `input_num=1`, `change_num=2`, so `input_num <= change_num` → the `max_change_amount` block is skipped.
3. The per-output check passes: `1_500_000 < 5_000_000` (min_input_amount).
4. PSBT is accepted; a 1.5 BTC change UTXO (exceeding `max_change_amount`) is registered in the bridge pool.

### Citations

**File:** contracts/satoshi-bridge/src/psbt.rs (L56-60)
```rust
        if utxo_num < config.passive_management_lower_limit {
            require!(input_num < change_num, "require input_num < change_num");
        } else if utxo_num > config.passive_management_upper_limit {
            require!(input_num > change_num, "require input_num > change_num");
        }
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L131-136)
```rust
                if force_healthy_output {
                    require!(
                        v.value.to_sat() > config.unhealthy_utxo_amount
                            && u128::from(v.value.to_sat()) <= config.max_change_amount,
                        "The output amount is not in the valid range"
                    );
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L202-205)
```rust
                    require!(
                        signer_is_unrestricted || output_value < min_input_amount,
                        "The change amount must be less than the smallest input, or the caller must have the UnrestrictedRelayer role"
                    );
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L227-237)
```rust
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
```
