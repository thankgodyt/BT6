### Title
Missing Orchard Halo2 Proof Verification Enables Permanent Stuck-State for User Funds — (File: `contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs`)

---

### Summary

The bridge's Orchard bundle validation never verifies the embedded Halo2 proof. It only decrypts the `out_ciphertext` using the hardcoded, publicly-known `BRIDGE_OVK = [0u8; 32]` and checks the recovered recipient address and value balance. An unprivileged user can submit a withdrawal with a bundle whose note contents pass all bridge checks but whose Halo2 proof is invalid. The bridge accepts the bundle, the MPC signs the transparent inputs, the transaction is broadcast, and the Zcash network rejects it. The user's nBTC tokens—already transferred to the bridge—are permanently stuck with no self-service recovery path.

---

### Finding Description

`extract_orchard_bundle` in `orchard_policy.rs` parses the bundle with `read_v5_bundle`, counts actions, and calls `recover_output_with_ovk` to decrypt the note ciphertext. It never calls any proof-verification routine on the `Bundle<Authorized, ZatBalance>` it returns.

```rust
// orchard_policy.rs L38-L78
pub fn extract_orchard_bundle(...) -> Result<Option<ParsedOrchardBundle>, String> {
    ...
    let bundle = read_v5_bundle(&mut reader, proof_size_enforcement)...;
    // ← no bundle.verify_proof() or equivalent
    let (note, addr, _memo) = bundle.recover_output_with_ovk(0, &ovk)...;
    ...
}
```

`validate_orchard_bundle` then checks only the recovered recipient address and the `value_balance` field read directly from the struct—both of which are independent of proof validity:

```rust
// orchard_policy.rs L86-L117
pub fn validate_orchard_bundle(...) -> Result<(), String> {
    // checks recipient address bytes
    // checks value_balance field
    // ← no proof verification
}
```

The `BRIDGE_OVK` is hardcoded to all-zero bytes, a publicly known constant. Because `ock = PRF^ock(ovk, cv, cm, ephemeral_key)` is fully computable by anyone who knows the OVK, an attacker can craft an `out_ciphertext` that decrypts to any desired note plaintext (correct recipient, correct amount) while the actual Halo2 proof commits to a completely different or syntactically invalid statement. The bridge's policy checks pass; the Zcash network's consensus rejects the transaction.

The withdrawal flow (per `CLAUDE.md` L47-L54) transfers nBTC tokens to the bridge at `ft_transfer_call` time and only burns them after `verify_withdraw` confirms on-chain inclusion. If the Zcash transaction is rejected, `verify_withdraw` can never succeed, and the `BTCPendingInfo` entry—along with the user's tokens—is permanently locked in bridge storage.

---

### Impact Explanation

**Medium — stuck bridge state requiring operator intervention.**

- The user's nBTC tokens are transferred to the bridge at withdrawal initiation and cannot be recovered without operator action.
- The bridge's selected UTXOs are locked inside the `BTCPendingInfo` record even though they were never spent on-chain.
- The `cancel_withdraw` RBF path requires the original transaction to be in the Zcash mempool; a transaction rejected for an invalid proof is never admitted to the mempool, so the standard self-service cancellation path does not apply.
- Repeated exploitation by multiple users could accumulate stuck pending records and drain the bridge's available UTXO liquidity.

---

### Likelihood Explanation

Any unprivileged Zcash bridge user can trigger this. The attacker needs only to:
1. Construct a syntactically valid Orchard bundle (parseable by `read_v5_bundle`) with a correct `out_ciphertext` (trivially crafted because `BRIDGE_OVK` is `[0u8; 32]`) and a correct `value_balance` field.
2. Replace the proof bytes with garbage.
3. Submit a normal withdrawal via `ft_transfer_call`.

No privileged access, leaked keys, or external dependencies are required.

---

### Recommendation

Before accepting an Orchard bundle, call the proof-verification API on the parsed `Bundle<Authorized, ZatBalance>`. In the `orchard` crate this is exposed via `Bundle::verify_proof` (or the equivalent `BatchValidator` path). Because Halo2 verification is computationally expensive and may exceed NEAR's per-transaction gas budget, the preferred mitigation is to **reject any withdrawal that includes an Orchard bundle at the contract level and require the user to pre-verify the proof off-chain and submit only the verified transaction bytes**, or to enforce proof verification in a separate, gas-budgeted callback. At minimum, document the missing check and add an operator-controlled emergency-withdrawal function so stuck funds can be returned without manual state surgery.

---

### Proof of Concept

1. Alice holds 200 000 nZEC and calls `ft_transfer_call` on the nBTC contract targeting the bridge, with a `Withdraw` message specifying a valid Unified Address UA and a crafted Orchard bundle:
   - `out_ciphertext` encrypted with `ock` derived from `BRIDGE_OVK=[0;32]`, decrypting to `(recipient=UA_orchard_receiver, amount=orchard_amount)`.
   - Proof field replaced with 2048 zero bytes (syntactically sized correctly for `ProofSizeEnforcement`).
   - `value_balance` field set to `-orchard_amount` (matching the bridge's check).
2. `ft_on_transfer_callback` calls `extract_orchard_bundle` → `read_v5_bundle` succeeds (bytes parse), `recover_output_with_ovk` succeeds (OVK known), recipient and value balance checks pass → `validate_orchard_bundle` returns `Ok(())`.
3. Bridge creates `BTCPendingInfo`, MPC signs the transparent UTXO inputs, emits `SignedBtcTransaction`.
4. Relayer broadcasts the transaction. Zcash consensus rejects it: invalid Halo2 proof.
5. No relayer can ever call `verify_withdraw` with a valid Merkle proof for this tx_id.
6. Alice's 200 000 nZEC remain in the bridge's account. The selected UTXOs are locked in the pending record. Operator intervention is required to unblock. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 
<cite repo="Lauraivanka/btc-bridge--002" path="contracts/satoshi-bridge/src/btc_light_client/withdraw.rs" start="70" end="82

### Citations

**File:** contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs (L9-11)
```rust
/// Bridge OVK used to recover outputs for policy checks.
/// Hardcoded to all zeroes for now; can be made configurable later.
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

**File:** contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs (L86-118)
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
}
```

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L77-83)
```rust
        let orchard = orchard_policy::extract_orchard_bundle(
            orchard_bundle_bytes,
            proof_size_enforcement(get_branch_id(current_height, config)),
        )
        .unwrap_or_else(|_| {
            env::panic_str("ERR_INVALID_ORCHARD_BUNDLE: failed to extract Orchard bundle")
        });
```
