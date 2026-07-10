### Title
Zcash Re-execution of `execute_refund` with a Different Orchard Bundle Creates Competing Refund PSBTs for the Same UTXO — (`contracts/satoshi-bridge/src/zcash_utils/refund.rs`)

---

### Summary

`load_refund_request_for_execute` intentionally permits re-execution of `execute_refund` once `refund_request.executed == true`. On Zcash, the `btc_pending_id` is the transaction's txid, which is derived from the full transaction content including the Orchard bundle. An unprivileged attacker can supply a structurally different Orchard bundle (same recipient, same amount, different randomness) to produce a different txid, bypassing the `"pending info already exist"` guard and inserting a second `BTCPendingInfo` for the same UTXO.

---

### Finding Description

**Gate that is intentionally open:**

`load_refund_request_for_execute` contains an explicit bypass:

```rust
require!(
    !self.data().verified_deposit_utxo.contains(utxo_storage_key)
        || refund_request.executed,
    "UTXO already verified via deposit, cannot refund"
);
``` [1](#0-0) 

The comment documents the intent: re-execution is allowed to re-create the refund tx after a consensus branch change. [2](#0-1) 

**How `btc_pending_id` is derived on Zcash:**

`get_pending_id()` on the Bitcoin side returns `compute_txid()` of the unsigned transaction. [3](#0-2) 

On Zcash, the `PsbtWrapper` embeds the Orchard bundle directly into the transaction structure. Two bundles with the same recipient and amount but different internal randomness (note commitment randomness, proof randomness) produce different txids, and therefore different `btc_pending_id` values. [4](#0-3) 

**Validation that does NOT block a second valid bundle:**

`check_psbt_chain_specific` → `validate_orchard_bundle` only checks:
1. The recovered recipient matches `refund_address`
2. The value balance equals the output amount [5](#0-4) [6](#0-5) 

A second bundle satisfying both constraints (same recipient, same amount, different randomness) passes all validation.

**The collision guard that is bypassed:**

```rust
require!(
    self.data_mut()
        .btc_pending_infos
        .insert(btc_pending_id.clone(), btc_pending_info.into())
        .is_none(),
    "pending info already exist"
);
``` [7](#0-6) 

Because the second bundle produces a different `btc_pending_id`, the `is_none()` check passes and a second `BTCPendingInfo` is inserted.

**Capacity check does not block a fresh attacker account:**

`require_pending_sign_capacity` checks the *caller's* pending count against a per-account limit (default: 1). [8](#0-7) 

A fresh attacker account (Bob) has 0 pending sign entries and passes this check.

---

### Impact Explanation

After the attack:
- Two `BTCPendingInfo` entries exist for the same deposit UTXO, each referencing a different Zcash transaction.
- The MPC signing pipeline will be invoked for both.
- Only one transaction can be confirmed on-chain (a UTXO can only be spent once).
- The stale entry cannot be cleaned up via `internal_remove_refund_pending_tx_id` while the refund request is still active (the guard `"refund request still active"` blocks it). [9](#0-8) 

No funds are stolen or redirected — the refund still pays the correct `refund_address`. The impact is a stuck bridge state requiring operator intervention to clean up the stale pending entry after `verify_refund_finalize` removes the request.

**Severity: Low** — publicly reachable invariant-violation / stuck-state in a production bridge path without direct theft.

---

### Likelihood Explanation

- `execute_refund` is a public, payable function callable by any account after the timelock.
- The attacker needs to craft a valid Orchard bundle with the same recipient and amount but different randomness. This is technically feasible for anyone with knowledge of the Zcash Orchard protocol and access to `BRIDGE_OVK` (used for output recovery validation).
- The attacker needs a fresh NEAR account with no existing pending sign entries.
- The window is open from when the first `execute_refund` succeeds until `verify_refund_finalize` removes the request.

---

### Recommendation

In `finalize_refund_with_psbt`, before inserting a new `BTCPendingInfo`, check whether any existing pending entry already references the same `utxo_storage_key` (via the VUTXO list or a dedicated index). If one exists and the refund request is already `executed`, reject the second call unless the existing pending entry has been explicitly removed first (e.g., via `internal_remove_refund_pending_tx_id`).

Alternatively, when `refund_request.executed == true`, require the caller to first remove the existing pending entry before re-executing, making the re-execution path explicit and atomic.

---

### Proof of Concept

1. Alice calls `execute_refund(key, Some(bundle_A))` after the timelock → `BTCPendingInfo{id: txid_A}` created, `executed=true`.
2. Bob (fresh account, 0 pending entries) calls `execute_refund(key, Some(bundle_B))` where `bundle_B` has the same recipient and amount as `bundle_A` but different randomness.
3. `load_refund_request_for_execute` passes (`executed == true`).
4. `check_psbt_chain_specific` passes (same recipient, same amount).
5. `psbt.get_pending_id()` returns `txid_B ≠ txid_A`.
6. `btc_pending_infos.insert(txid_B, ...)` returns `None` → guard passes.
7. `BTCPendingInfo{id: txid_B}` is inserted.
8. Bridge now has two competing refund PSBTs (`txid_A`, `txid_B`) for the same UTXO. Only one can confirm on-chain; the other is permanently stuck until operator cleanup.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L250-258)
```rust
        // Block only if the UTXO was claimed by a deposit. If it was claimed by
        // our own refund (executed == true, which also set verified_deposit_utxo),
        // re-running execute_refund is allowed — re-creating the refund tx, e.g.
        // after a consensus branch change.
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L366-372)
```rust
        require!(
            self.data_mut()
                .btc_pending_infos
                .insert(btc_pending_id.clone(), btc_pending_info.into())
                .is_none(),
            "pending info already exist"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L418-424)
```rust
        require!(
            !self
                .data()
                .refund_requests
                .contains_key(&utxo_storage_keys[0]),
            "refund request still active"
        );
```

**File:** contracts/satoshi-bridge/src/bitcoin_utils/psbt_wrapper.rs (L127-134)
```rust
    pub fn get_pending_id(&self) -> String {
        self.psbt
            .clone()
            .extract_tx()
            .expect("ERR_EXTRACT_TX: failed to extract transaction from PSBT")
            .compute_txid()
            .to_string()
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L85-93)
```rust
        Self {
            branch_id: get_branch_id(current_height, config),
            expiry_height,
            vout,
            vin,
            inputs_utxo: inputs,
            orchard,
            recipient_address,
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

**File:** contracts/satoshi-bridge/src/account.rs (L113-123)
```rust
    pub fn require_pending_sign_capacity(&self, account_id: &AccountId) {
        require!(
            self.get_account(account_id)
                .unwrap_or_else(|| {
                    env::panic_str(&format!("ERR_ACCOUNT_NOT_REGISTERED: {}", account_id))
                })
                .pending_sign_count()
                < self.get_max_pending_sign_txs(account_id),
            "Too many pending sign transactions"
        );
    }
```
