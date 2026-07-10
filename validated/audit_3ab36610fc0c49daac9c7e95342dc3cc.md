### Title
Wrong `EXPECTED_ACTIONS_NUMBER` Constant Causes All Orchard Bundle Withdrawals to Revert - (File: contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs)

### Summary
The constant `EXPECTED_ACTIONS_NUMBER = 1` in `orchard_policy.rs` is used to enforce an exact action count on every submitted Orchard bundle. The Orchard protocol builder (`orchard::builder`) enforces a minimum of 2 actions per bundle for privacy (referenced in the constant's own comment: `https://github.com/zcash/orchard/blob/main/src/builder.rs#L36`). Because every real bundle produced by the builder has at least 2 actions, the check `bundle.actions().len() != EXPECTED_ACTIONS_NUMBER` always evaluates to `true`, causing `extract_orchard_bundle` to return an `Err` on every call. This makes all Zcash withdrawals to shielded Orchard addresses permanently unreachable.

### Finding Description
In `orchard_policy.rs`, the constant is declared as:

```rust
/// Minimum number of actions required in an Orchard bundle per the Orchard protocol.
/// The Orchard builder automatically pads bundles to meet this minimum for privacy.
/// See: https://github.com/zcash/orchard/blob/main/src/builder.rs#L36
pub const EXPECTED_ACTIONS_NUMBER: usize = 1;
``` [1](#0-0) 

The comment itself acknowledges that the Orchard builder **automatically pads** bundles to meet the minimum for privacy. The referenced line in the upstream `orchard` crate defines `MIN_ACTIONS = 2`. This means every bundle produced by the builder for a single-output withdrawal contains exactly 2 actions (1 real + 1 dummy for privacy), never 1.

The enforcement check immediately below rejects any bundle whose action count differs from `1`:

```rust
if bundle.actions().len() != EXPECTED_ACTIONS_NUMBER {
    return Err(format!(
        "Orchard bundle must have {} actions, got {}",
        EXPECTED_ACTIONS_NUMBER,
        bundle.actions().len()
    ));
}
``` [2](#0-1) 

Because every real bundle has `actions().len() == 2`, this condition is always `true`, and `extract_orchard_bundle` always returns `Err(...)`.

`extract_orchard_bundle` is called inside `PsbtWrapper::new` and `PsbtWrapper::from_original_psbt`, both of which call `unwrap_or_else(|_| env::panic_str(...))`: [3](#0-2) 

This panic propagates through `ft_on_transfer_callback`, which is the NEAR cross-contract callback invoked during every Zcash withdrawal to a shielded address.

### Impact Explanation
**Medium.** Every Zcash withdrawal to a shielded Orchard address panics inside `ft_on_transfer_callback`. In NEAR's `ft_transfer_call` flow, a panicking callback causes the promise to fail and the nZEC tokens are refunded to the sender — so there is no permanent token loss. However, the Orchard withdrawal path is completely non-functional: no user can ever successfully withdraw nZEC to a shielded address. This constitutes a broken callback/rollback and a stuck bridge state for the entire Orchard withdrawal feature, requiring operator intervention (contract upgrade) to fix.

### Likelihood Explanation
**High.** The failure is deterministic: any user who submits a withdrawal to a shielded Zcash Unified Address with an Orchard bundle will trigger the panic. The Orchard builder always produces bundles with `MIN_ACTIONS = 2`, so the wrong constant is hit on every single invocation of the Orchard withdrawal path.

### Recommendation
Change the constant to match the actual minimum enforced by the Orchard builder:

```diff
- pub const EXPECTED_ACTIONS_NUMBER: usize = 1;
+ pub const EXPECTED_ACTIONS_NUMBER: usize = 2;
``` [4](#0-3) 

Alternatively, if the intent is to accept any bundle with at least the minimum number of actions, change the check from an equality to a lower-bound:

```diff
- if bundle.actions().len() != EXPECTED_ACTIONS_NUMBER {
+ if bundle.actions().len() < EXPECTED_ACTIONS_NUMBER {
```

### Proof of Concept
1. User holds nZEC and calls `ft_transfer_call` on the nZEC contract, targeting the bridge with a withdrawal message specifying a shielded Zcash Unified Address and an Orchard bundle built with the standard `orchard::builder`.
2. The bridge's `ft_on_transfer` dispatches `ft_on_transfer_callback` via a cross-contract call.
3. Inside `ft_on_transfer_callback`, `PsbtWrapper::new` is called with the user-supplied `orchard_bundle_bytes`.
4. `PsbtWrapper::new` calls `extract_orchard_bundle`, which reads the bundle and finds `bundle.actions().len() == 2`.
5. The check `2 != 1` is `true`; `extract_orchard_bundle` returns `Err(...)`.
6. `unwrap_or_else(|_| env::panic_str("ERR_INVALID_ORCHARD_BUNDLE: ..."))` panics.
7. The callback fails; NEAR refunds the nZEC to the user.
8. The withdrawal is permanently impossible without a contract upgrade. [3](#0-2) [2](#0-1)

### Citations

**File:** contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs (L13-16)
```rust
/// Minimum number of actions required in an Orchard bundle per the Orchard protocol.
/// The Orchard builder automatically pads bundles to meet this minimum for privacy.
/// See: https://github.com/zcash/orchard/blob/main/src/builder.rs#L36
pub const EXPECTED_ACTIONS_NUMBER: usize = 1;
```

**File:** contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs (L49-55)
```rust
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
