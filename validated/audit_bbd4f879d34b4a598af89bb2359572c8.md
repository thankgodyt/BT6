### Title
Wrong Orchard Action Count Constant Rejects All Shielded Zcash Withdrawals - (File: `contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs`)

### Summary
`EXPECTED_ACTIONS_NUMBER` is hardcoded to `1`, but the Orchard protocol mandates a minimum of **2** actions per bundle (the Orchard builder always pads to `MIN_ACTIONS = 2` for privacy). Every real Orchard bundle submitted by a user will have ≥ 2 actions, causing the strict equality check to always fail and permanently blocking all shielded Zcash withdrawals.

### Finding Description
In `orchard_policy.rs`, the constant is defined as:

```rust
pub const EXPECTED_ACTIONS_NUMBER: usize = 1;
```

The accompanying comment even cites the Orchard builder source (`https://github.com/zcash/orchard/blob/main/src/builder.rs#L36`) where `MIN_ACTIONS = 2` is defined — the exact value the constant should hold. [1](#0-0) 

`extract_orchard_bundle` enforces this constant with a strict equality check:

```rust
if bundle.actions().len() != EXPECTED_ACTIONS_NUMBER {
    return Err(format!(
        "Orchard bundle must have {} actions, got {}",
        EXPECTED_ACTIONS_NUMBER,
        bundle.actions().len()
    ));
}
``` [2](#0-1) 

Because every standard Orchard bundle produced by a Zcash wallet has at least 2 actions, `bundle.actions().len()` is always ≥ 2, so `!= 1` is always `true`, and `extract_orchard_bundle` always returns an `Err`.

`PsbtWrapper::new` calls `extract_orchard_bundle` and panics on error:

```rust
let orchard = orchard_policy::extract_orchard_bundle(
    orchard_bundle_bytes,
    proof_size_enforcement(get_branch_id(current_height, config)),
)
.unwrap_or_else(|_| {
    env::panic_str("ERR_INVALID_ORCHARD_BUNDLE: failed to extract Orchard bundle")
});
``` [3](#0-2) 

The same constant is also used in `shielded_refund_min_fee`, causing the ZIP-317 fee floor for shielded refunds to be computed with 1 Orchard action instead of 2, underestimating the required fee: [4](#0-3) 

### Impact Explanation
Every user who attempts a shielded Zcash withdrawal (i.e., calls `ft_transfer_call` on the nBTC contract with an Orchard bundle targeting a shielded address) triggers `ft_on_transfer_callback` → `PsbtWrapper::new` → panic. The entire shielded withdrawal path is permanently broken. Depending on how the nBTC contract handles a panicking `ft_on_transfer` callback, user tokens may be stuck in an unresolvable state requiring operator intervention. This matches the **Medium** impact class: broken callback rollback / stuck bridge state requiring operator intervention.

### Likelihood Explanation
Any unprivileged NEAR account holding nZEC who attempts a shielded withdrawal to a Zcash unified address with an Orchard receiver will trigger this path. No special privileges or unusual conditions are required — it is the normal shielded withdrawal flow.

### Recommendation
Change the constant to match the Orchard protocol specification:

```diff
-pub const EXPECTED_ACTIONS_NUMBER: usize = 1;
+pub const EXPECTED_ACTIONS_NUMBER: usize = 2;
``` [5](#0-4) 

This aligns the bridge with the Orchard builder's `MIN_ACTIONS = 2` guarantee (referenced in the comment on line 15) and ensures that real Orchard bundles pass the action-count check. The `shielded_refund_min_fee` calculation will also become correct automatically.

### Proof of Concept
1. User holds nZEC and calls `ft_transfer_call` on the nZEC contract, passing a valid Orchard bundle (produced by any standard Zcash wallet) as `chain_specific_data.orchard_bundle_bytes`.
2. The bridge's `ft_on_transfer` dispatches to `ft_on_transfer_withdraw_chain_specific`, which schedules `ft_on_transfer_callback`.
3. Inside `ft_on_transfer_callback`, `PsbtWrapper::new` is called with the Orchard bundle bytes.
4. `extract_orchard_bundle` reads the bundle; `bundle.actions().len()` returns 2 (the Orchard builder minimum).
5. The check `2 != 1` is `true` → `Err(...)` is returned.
6. `unwrap_or_else` fires `env::panic_str("ERR_INVALID_ORCHARD_BUNDLE: ...")`.
7. The callback panics; the shielded withdrawal fails for every user on every attempt. [6](#0-5) [3](#0-2) [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs (L13-16)
```rust
/// Minimum number of actions required in an Orchard bundle per the Orchard protocol.
/// The Orchard builder automatically pads bundles to meet this minimum for privacy.
/// See: https://github.com/zcash/orchard/blob/main/src/builder.rs#L36
pub const EXPECTED_ACTIONS_NUMBER: usize = 1;
```

**File:** contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs (L38-55)
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

**File:** contracts/satoshi-bridge/src/zcash_utils/refund.rs (L57-59)
```rust
fn shielded_refund_min_fee() -> u128 {
    zip317_min_fee(1, vec![], EXPECTED_ACTIONS_NUMBER).into_u64() as u128
}
```

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L120-136)
```rust
    ) -> U128 {
        let expiry_height = self.get_expiry_height(&chain_specific_data, last_block_height);
        let orchard_bundle = chain_specific_data.map(|c| c.orchard_bundle_bytes.0);

        let psbt = PsbtWrapper::new(
            input,
            output,
            orchard_bundle,
            expiry_height,
            last_block_height,
            Some(target_btc_address.clone()),
            self.internal_config(),
        );

        self.create_btc_pending_info(sender_id, amount.0, target_btc_address, psbt, max_gas_fee);

        U128(0)
```
