### Title
Wrong Orchard Action Count Constant Permanently Blocks Zcash Shielded Withdrawals - (File: contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs)

### Summary
`EXPECTED_ACTIONS_NUMBER` is set to `1`, but the Orchard protocol's own builder enforces a minimum of `2` actions per bundle. The bridge enforces an exact equality check (`!= EXPECTED_ACTIONS_NUMBER`), so every standard Zcash wallet bundle (which has ≥ 2 actions) is unconditionally rejected. Zcash shielded withdrawals are permanently broken for any user relying on a standard wallet.

### Finding Description
In `contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs`, the constant and its guard are:

```rust
/// Minimum number of actions required in an Orchard bundle per the Orchard protocol.
/// The Orchard builder automatically pads bundles to meet this minimum for privacy.
/// See: https://github.com/zcash/orchard/blob/main/src/builder.rs#L36
pub const EXPECTED_ACTIONS_NUMBER: usize = 1;
``` [1](#0-0) 

```rust
if bundle.actions().len() != EXPECTED_ACTIONS_NUMBER {
    return Err(format!(
        "Orchard bundle must have {} actions, got {}",
        EXPECTED_ACTIONS_NUMBER,
        bundle.actions().len()
    ));
}
``` [2](#0-1) 

The developer's own comment references `https://github.com/zcash/orchard/blob/main/src/builder.rs#L36`, which is `pub const MIN_ACTIONS: usize = 2;`. The constant is therefore set to the wrong value (1 instead of 2), and the check uses strict equality (`!=`) rather than a minimum (`<`). Any standard Orchard bundle produced by a real Zcash wallet is padded to at least 2 actions for privacy and will always fail this check.

The test harness works around this by using `BundleType::Coinbase`, a special non-standard bundle type that bypasses the 2-action minimum:

```rust
// Use Coinbase bundle type which supports single output without dummy actions
let mut builder = Builder::new(BundleType::Coinbase, Anchor::empty_tree());
``` [3](#0-2) 

This masks the defect in tests while leaving production users unable to submit valid bundles.

The `extract_orchard_bundle` function is called from `PsbtWrapper::new` during withdrawal initiation: [4](#0-3) 

When it returns an error, `PsbtWrapper::new` panics with `ERR_INVALID_ORCHARD_BUNDLE`, aborting the `ft_on_transfer` callback and reverting the nZEC transfer. The user's tokens are returned, but the withdrawal cannot be completed.

The same constant is also used in fee estimation for shielded refunds: [5](#0-4) 

If the constant were corrected to 2, the fee estimate would also need to be re-verified.

### Impact Explanation
Every nZEC holder who attempts a shielded Zcash withdrawal using a standard wallet is permanently blocked. The bridge's Zcash shielded withdrawal path is entirely non-functional for real-world usage. This constitutes a stuck bridge state requiring operator intervention (contract upgrade or constant correction) to resolve. No funds are directly stolen, but the core Zcash shielded withdrawal feature is permanently inoperable.

**Severity: Medium** — matches "stuck bridge state requiring operator intervention."

### Likelihood Explanation
Likelihood is high. Any user who attempts a Zcash shielded withdrawal with a standard wallet will encounter this failure on every attempt. The defect is deterministic and affects 100% of standard-wallet Orchard bundles. No special attacker capability is required; ordinary bridge usage triggers it.

### Recommendation
1. Correct the constant to match the Orchard protocol minimum:
   ```rust
   pub const EXPECTED_ACTIONS_NUMBER: usize = 2;
   ```
2. Change the guard from an exact equality check to a minimum check, or keep exact equality if the bridge intentionally restricts to exactly 2 actions:
   ```rust
   if bundle.actions().len() < EXPECTED_ACTIONS_NUMBER { ... }
   ```
3. Update `shielded_refund_min_fee` to pass the corrected constant and re-verify the fee covers the actual ZIP-317 cost.
4. Replace `BundleType::Coinbase` in tests with `BundleType::Transact` (the standard type) so tests exercise the same bundle structure that production users submit.

### Proof of Concept
1. Alice holds nZEC on NEAR and calls `ft_transfer_call` targeting the bridge, with a `TokenReceiverMessage::Withdraw` containing a standard Orchard bundle (2 actions, produced by any real Zcash wallet).
2. The bridge's `ft_on_transfer` → `internal_withdraw` → `PsbtWrapper::new` → `extract_orchard_bundle` executes the check:
   ```
   bundle.actions().len() (= 2) != EXPECTED_ACTIONS_NUMBER (= 1)  →  true
   ```
   Returns `Err("Orchard bundle must have 1 actions, got 2")`.
3. `PsbtWrapper::new` panics with `ERR_INVALID_ORCHARD_BUNDLE`.
4. The NEAR transaction reverts; Alice's nZEC is returned.
5. Alice cannot withdraw to any shielded Zcash address regardless of how many times she retries, because every standard wallet produces ≥ 2-action bundles.
6. The only workaround requires crafting a non-standard `BundleType::Coinbase` bundle — knowledge not available to ordinary users and not supported by standard wallets.

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

**File:** contracts/satoshi-bridge/tests/setup/orchard.rs (L33-34)
```rust
    // Use Coinbase bundle type which supports single output without dummy actions
    let mut builder = Builder::new(BundleType::Coinbase, Anchor::empty_tree());
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

**File:** contracts/satoshi-bridge/src/zcash_utils/refund.rs (L57-58)
```rust
fn shielded_refund_min_fee() -> u128 {
    zip317_min_fee(1, vec![], EXPECTED_ACTIONS_NUMBER).into_u64() as u128
```
