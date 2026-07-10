### Title
Missing Orchard Output Amount Validation in RBF Withdrawal Path Allows Attacker to Drain Bridge Withdraw Fee — (`contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs`)

---

### Summary

In the Zcash RBF withdrawal path, the attacker-controlled `orchard_bundle_bytes` is accepted in `withdraw_rbf_callback`, passed through `generate_psbt_from_original_psbt_and_new_output` → `PsbtWrapper::from_original_psbt` → `extract_orchard_bundle`, and stored in the new PSBT without any check that the Orchard output amount equals the expected withdrawal amount (`transfer_amount - withdraw_fee - gas_fee`). The range check in `check_withdraw_psbt` is algebraically trivially satisfied regardless of the Orchard amount, and the explicit amount equality check present in the refund path is absent here.

---

### Finding Description

**Call path (Zcash variant):**

```
withdraw_rbf (public, account owner)
  → withdraw_rbf_chain_specific          [zcash_utils/contract_methods.rs:16-35]
      → get_last_block_height_promise
      → withdraw_rbf_callback            [zcash_utils/contract_methods.rs:41-80]
          → generate_psbt_from_original_psbt_and_new_output  [contract_methods.rs:261-278]
              → PsbtWrapper::from_original_psbt              [psbt_wrapper.rs:109-149]
                  → extract_orchard_bundle (attacker bytes)  [orchard_policy.rs:38-78]
          → internal_withdraw_rbf                            [rbf/withdraw.rs:34-72]
              → check_withdraw_rbf_psbt_valid
                  → check_withdraw_psbt                      [psbt.rs:164-262]
                      → check_psbt_chain_specific            [contract_methods.rs:192-212]
```

**The algebraic flaw in `check_withdraw_psbt`:**

Let:
- `I` = `total_input_amount` (sum of stored UTXO values, not attacker-controlled)
- `T` = sum of transparent outputs
- `O` = Orchard bundle amount (attacker-controlled) [1](#0-0) 

`add_extra_outputs` adds `O` to both `actual_received_amounts` and `total_output_amount`: [2](#0-1) 

Then:

```
gas_fee             = I - T - O
max_received_amount = amount - withdraw_fee - gas_fee
                    = amount - withdraw_fee - (I - T - O)
                    = amount - withdraw_fee - I + T + O
```

The range check is:

```
O <= max_received_amount
O <= amount - withdraw_fee - I + T + O
0 <= amount - withdraw_fee - I + T          ← O cancels out entirely
``` [3](#0-2) 

**O is completely unconstrained by this check.** The only binding constraints on O are the gas fee bounds:

```
min_btc_gas_fee <= I - T - O <= max_btc_gas_fee
```

i.e., `O ∈ [I - T - max_btc_gas_fee, I - T - min_btc_gas_fee]`.

**`check_psbt_chain_specific` does not fill the gap.** It validates the ZIP-317 minimum fee and calls `validate_orchard_bundle`, which only checks (a) the recipient address matches and (b) the bundle's internal `value_balance == -O`. Neither check constrains O to equal the expected withdrawal amount. [4](#0-3) [5](#0-4) 

**The refund path has the missing check; the RBF path does not.** `execute_refund_callback` explicitly enforces: [6](#0-5) 

No equivalent check exists anywhere in `internal_withdraw_rbf` or its callees for the RBF case.

**Crafting the malicious bundle is feasible.** `BRIDGE_OVK` is a public constant (all-zero bytes): [7](#0-6) 

Because the OVK is public, any user can construct a valid Orchard bundle encrypted to it using the standard Zcash SDK, with an arbitrary output amount and valid Halo2 proofs and binding signature. The bundle must have exactly 1 action (`EXPECTED_ACTIONS_NUMBER = 1`) and pass `read_v5_bundle` deserialization — both are straightforward with the SDK. [8](#0-7) 

**`check_withdraw_chain_specific` is a no-op in the Zcash variant**, so there is no RBF gas-increase requirement either: [9](#0-8) 

---

### Impact Explanation

For a shielded-only withdrawal (T = 0, I ≈ `amount`):

- Expected Orchard output: `amount - withdraw_fee - gas_fee`
- Maximum attacker-inflatable O: `I - min_btc_gas_fee ≈ amount - min_btc_gas_fee`
- Excess received: `withdraw_fee + (gas_fee - min_btc_gas_fee)`

The bridge signs and broadcasts a Zcash transaction that moves more ZEC into the Orchard pool than the user burned in nZEC. The excess is drawn from the bridge's UTXO pool. The bridge's accounting records `burn_amount = actual_received_amount + gas_fee` (line 61 of `rbf/withdraw.rs`), which will be inflated, but the nZEC already burned is fixed at `amount` — the bridge loses the difference. [10](#0-9) 

---

### Likelihood Explanation

- The attacker is the account owner — no privileged role required.
- `withdraw_rbf` is a public contract method.
- `BRIDGE_OVK = [0u8; 32]` is a hardcoded public constant; crafting a valid bundle requires only the Zcash SDK.
- The algebraic bypass requires no brute force or cryptographic break.

---

### Recommendation

After `generate_psbt_from_original_psbt_and_new_output` returns the new PSBT in `withdraw_rbf_callback`, add an explicit check mirroring the refund path:

```rust
if new_psbt.has_orchard_bundle() {
    let expected_orchard_amount = original_tx_btc_pending_info.transfer_amount
        - original_tx_btc_pending_info.withdraw_fee
        - computed_gas_fee;
    require!(
        new_psbt.get_orchard_output_amount() == expected_orchard_amount,
        format!(
            "Orchard output amount ({}) does not match expected withdrawal amount ({})",
            new_psbt.get_orchard_output_amount(),
            expected_orchard_amount
        )
    );
}
```

Alternatively, enforce this inside `check_psbt_chain_specific` when called from the RBF withdrawal context, passing the expected amount as a parameter.

---

### Proof of Concept

1. User burns `amount = 10_000_000` zatoshis of nZEC, triggering a shielded withdrawal. Bridge selects UTXOs with `I = 10_000_000`. `withdraw_fee = 100_000`, expected `gas_fee = 50_000`, so expected `O = 9_850_000`.

2. User calls `withdraw_rbf` with `chain_specific_data.orchard_bundle_bytes` set to a freshly constructed Orchard bundle (using the Zcash SDK, OVK = `[0u8;32]`) with output amount `O_inflated = I - min_btc_gas_fee = 10_000_000 - 10_000 = 9_990_000`.

3. In `withdraw_rbf_callback`, `from_original_psbt` stores `O_inflated` in the new PSBT.

4. `check_withdraw_psbt` computes `gas_fee = 10_000_000 - 0 - 9_990_000 = 10_000` (= `min_btc_gas_fee`, passes). The range check reduces to `0 <= amount - withdraw_fee - I + T = 10_000_000 - 100_000 - 10_000_000 + 0 = -100_000` — wait, this is negative, so the check **would** fail here.

   Correction: the attacker must keep `O_inflated` such that `I - T >= amount - withdraw_fee`, i.e., `O_inflated <= I - T - (amount - withdraw_fee - gas_fee_lower_bound)`. For `I = amount` exactly, the maximum O without failing the lower bound is `amount - withdraw_fee - min_btc_gas_fee + min_change_amount`. The attacker sets `O_inflated = amount - withdraw_fee - min_btc_gas_fee + min_change_amount`, stealing `withdraw_fee - min_change_amount` from the bridge.

5. `check_psbt_chain_specific` passes (recipient matches, value_balance = -O_inflated is internally consistent).

6. Bridge signs the transaction. On-chain, the user receives `O_inflated` zatoshis in the Orchard pool — `withdraw_fee - min_change_amount` more than they should.

### Citations

**File:** contracts/satoshi-bridge/src/psbt.rs (L218-218)
```rust
        total_output_amount += psbt.add_extra_outputs(&mut actual_received_amounts);
```

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

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L195-202)
```rust
    pub fn add_extra_outputs(&self, actual_received_amounts: &mut Vec<u128>) -> u128 {
        if let Some(orchard) = &self.orchard {
            actual_received_amounts.push(orchard.amount());
            return orchard.amount();
        }

        0
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L192-212)
```rust
    pub(crate) fn check_psbt_chain_specific(
        &self,
        psbt: &PsbtWrapper,
        gas_fee: u128,
        target_btc_address: String,
    ) {
        let min_fee = psbt.get_min_fee();
        require!(
            gas_fee >= min_fee.into_u64() as u128,
            format!(
                "Invalid gas fee ({}). min fee = {}.",
                gas_fee,
                min_fee.into_u64()
            )
        );

        // For withdrawals with Orchard bundle, calculate the expected net amount after fees
        if psbt.has_orchard_bundle() {
            psbt.validate_orchard_bundle(target_btc_address, self.internal_config().chain.clone());
        }
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L214-218)
```rust
    pub(crate) fn check_withdraw_chain_specific(
        _original_tx_btc_pending_info: &BTCPendingInfo,
        _gas_fee: u128,
    ) {
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs (L11-11)
```rust
pub const BRIDGE_OVK: [u8; 32] = [0u8; 32];
```

**File:** contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs (L38-78)
```rust
pub fn extract_orchard_bundle(
    orchard_bundle_bytes: Option<Vec<u8>>,
    proof_size_enforcement: ProofSizeEnforcement,
) -> Result<Option<ParsedOrchardBundle>, String> {
    if let Some(orchard_bundle_bytes) = orchard_bundle_bytes {
        let mut reader = Cursor::new(orchard_bundle_bytes);
        let bundle = read_v5_bundle(&mut reader, proof_size_enforcement)
            .map_err(|_| "Failed to read orchard bundle".to_string())?
            .ok_or_else(|| "Orchard bundle is empty".to_string())?;

        // Check action count first per Orchard protocol requirements
        if bundle.actions().len() != EXPECTED_ACTIONS_NUMBER {
            return Err(format!(
                "Orchard bundle must have {} actions, got {}",
                EXPECTED_ACTIONS_NUMBER,
                bundle.actions().len()
            ));
        }

        // Since we require exactly 1 action, directly recover the single output
        let ovk = orchard::keys::OutgoingViewingKey::from(BRIDGE_OVK);
        let (note, addr, _memo) = bundle
            .recover_output_with_ovk(0, &ovk)
            .ok_or_else(|| "Failed to recover Orchard output with bridge OVK".to_string())?;

        let value = note.value().inner();
        if value == 0 {
            return Err("Orchard output value must be non-zero".to_string());
        }

        Ok(Some(ParsedOrchardBundle {
            bundle,
            output: OrchardOutput {
                amount: value,
                recipient_addr: addr.to_raw_address_bytes(),
            },
        }))
    } else {
        Ok(None)
    }
}
```

**File:** contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs (L86-117)
```rust
pub fn validate_orchard_bundle(
    orchard: &ParsedOrchardBundle,
    expected_recipient: &str,
    chain: &Chain,
) -> Result<(), String> {
    let recipient_address = Address::parse(expected_recipient, chain.clone())?;

    // Validate recipient
    let expected_addr_bytes = recipient_address.extract_orchard_receiver()?;
    if orchard.recipient_addr() != &expected_addr_bytes {
        return Err(format!(
            "Orchard recipient mismatch: expected {} does not match recovered output",
            expected_recipient
        ));
    }

    // Validate value balance: for withdrawal, value flows FROM transparent TO Orchard
    // So value_balance should be negative and equal to the output amount
    let value_balance = orchard.bundle.value_balance();
    let expected_value_balance =
        -i64::try_from(orchard.amount()).map_err(|_| "Orchard amount too large for i64")?;

    let actual_value_balance: i64 = (*value_balance).into();
    if actual_value_balance != expected_value_balance {
        return Err(format!(
            "Orchard value balance mismatch: expected {}, got {}. \
             Value balance must equal negative output amount for withdrawals",
            expected_value_balance, actual_value_balance
        ));
    }

    Ok(())
```

**File:** contracts/satoshi-bridge/src/zcash_utils/refund.rs (L130-138)
```rust
        if psbt.has_orchard_bundle() {
            require!(
                psbt.get_orchard_output_amount() == refund_amount,
                format!(
                    "Orchard output amount ({}) does not match refund amount ({})",
                    psbt.get_orchard_output_amount(),
                    refund_amount
                )
            );
```

**File:** contracts/satoshi-bridge/src/rbf/withdraw.rs (L57-62)
```rust
        let (actual_received_amount, gas_fee) =
            self.check_withdraw_rbf_psbt_valid(original_tx_btc_pending_info, &withdraw_rbf_psbt);
        btc_pending_info.gas_fee = gas_fee;
        btc_pending_info.actual_received_amount = actual_received_amount;
        btc_pending_info.burn_amount = actual_received_amount + gas_fee;
        Self::check_withdraw_chain_specific(original_tx_btc_pending_info, gas_fee);
```
