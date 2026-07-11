### Title
`EXPECTED_ACTIONS_NUMBER` Hardcoded to 1 Rejects All Standard Orchard Bundles, Breaking Shielded Zcash Withdrawal and Refund Paths — (File: `contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs`)

---

### Summary

The bridge hardcodes `EXPECTED_ACTIONS_NUMBER = 1` and enforces an exact equality check on Orchard bundle action count. Standard Zcash wallets use `BundleType::Transactional`, which pads bundles to a minimum of 2 actions for privacy. Any user submitting a standard wallet-generated Orchard bundle for a shielded withdrawal or shielded refund will trigger a panic, making the entire shielded path permanently unreachable for standard wallet users.

---

### Finding Description

In `contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs`, the constant is defined as:

```rust
pub const EXPECTED_ACTIONS_NUMBER: usize = 1;
``` [1](#0-0) 

The developer comment references `https://github.com/zcash/orchard/blob/main/src/builder.rs#L36`, which is precisely where the Orchard crate defines `MIN_ACTIONS = 2`. The intent was to use the Orchard protocol minimum, but the value was set to 1 instead of 2.

`extract_orchard_bundle` enforces strict equality:

```rust
if bundle.actions().len() != EXPECTED_ACTIONS_NUMBER {
    return Err(format!(
        "Orchard bundle must have {} actions, got {}",
        EXPECTED_ACTIONS_NUMBER,
        bundle.actions().len()
    ));
}
``` [2](#0-1) 

This error propagates to a `panic` in both the withdrawal path (`PsbtWrapper::from_original_psbt`) and the refund path (`execute_refund_callback`): [3](#0-2) 

The test setup works around this by explicitly using `BundleType::Coinbase`, which is the only bundle type that produces exactly 1 action without padding:

```rust
// Use Coinbase bundle type which supports single output without dummy actions
let mut builder = Builder::new(BundleType::Coinbase, Anchor::empty_tree());
``` [4](#0-3) 

Standard Zcash wallets use `BundleType::Transactional`, which pads to at least 2 actions. `BundleType::Coinbase` is semantically reserved for mining coinbase transactions, not user withdrawals. The mismatch means the production bridge only accepts non-standard, coinbase-type bundles that no real Zcash wallet would produce for a withdrawal.

The same constant is also used in the refund fee calculation, compounding the inconsistency: [5](#0-4) 

---

### Impact Explanation

**Low. Publicly reachable panic-driven fault in production bridge/token paths without direct theft.**

- **Shielded withdrawals**: Any user calling `ft_transfer_call` with a standard Transactional Orchard bundle (≥ 2 actions) causes `ft_on_transfer` to panic. Under NEP-141, the panic causes the token transfer to be reverted, so nZEC is returned. No fund loss, but the shielded withdrawal path is completely broken for all standard wallet users.
- **Shielded refunds**: Any user calling `execute_refund` with a standard Transactional Orchard bundle causes `execute_refund_callback` to panic. The refund request remains in storage and can be retried, but only with a non-standard Coinbase bundle that real wallets do not produce.

The entire shielded Zcash withdrawal and refund surface is unreachable for any user with a standard Zcash wallet.

---

### Likelihood Explanation

**High.** Every standard Zcash wallet (Zashi, YWallet, etc.) uses `BundleType::Transactional` and produces bundles with ≥ 2 actions. Any user attempting a shielded withdrawal or shielded refund with a real wallet will hit this panic unconditionally. The only way to succeed is to craft a non-standard `BundleType::Coinbase` bundle, which is not a user-facing wallet feature.

---

### Recommendation

1. Replace the strict equality check with a minimum check: accept bundles with `actions().len() >= 1` (or `>= 2` to match the Orchard Transactional minimum).
2. Update the output-recovery loop to iterate over all actions and find the one recoverable with `BRIDGE_OVK`, rather than assuming index 0 is always the bridge output.
3. Verify that exactly one action in the bundle is recoverable with `BRIDGE_OVK` (to prevent multi-output bundles from smuggling extra value).
4. Update `EXPECTED_ACTIONS_NUMBER` to reflect the actual Orchard Transactional minimum (2), or remove the constant and use a range check.

---

### Proof of Concept

1. A user holds nZEC and calls `ft_transfer_call` on the nZEC contract targeting the bridge, with a `Withdraw` message containing a standard Zcash wallet-generated Orchard bundle (2 actions, as produced by `BundleType::Transactional`).
2. The bridge's `ft_on_transfer` → `ft_on_transfer_withdraw_chain_specific` → `PsbtWrapper::from_original_psbt` → `extract_orchard_bundle` executes the check `bundle.actions().len() != 1` → `true` (bundle has 2 actions).
3. `extract_orchard_bundle` returns `Err(...)`, `from_original_psbt` calls `env::panic_str("ERR_INVALID_ORCHARD_BUNDLE: failed to extract Orchard bundle")`.
4. The entire `ft_on_transfer` call panics; nZEC is refunded by the NEP-141 standard.
5. The user cannot complete a shielded withdrawal regardless of how many times they retry, because every standard wallet produces ≥ 2 actions. [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs (L13-16)
```rust
/// Minimum number of actions required in an Orchard bundle per the Orchard protocol.
/// The Orchard builder automatically pads bundles to meet this minimum for privacy.
/// See: https://github.com/zcash/orchard/blob/main/src/builder.rs#L36
pub const EXPECTED_ACTIONS_NUMBER: usize = 1;
```

**File:** contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs (L48-55)
```rust
        // Check action count first per Orchard protocol requirements
        if bundle.actions().len() != EXPECTED_ACTIONS_NUMBER {
            return Err(format!(
                "Orchard bundle must have {} actions, got {}",
                EXPECTED_ACTIONS_NUMBER,
                bundle.actions().len()
            ));
        }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L132-138)
```rust
        let orchard = orchard_policy::extract_orchard_bundle(
            orchard_bundle_bytes,
            proof_size_enforcement(get_branch_id(current_height, config)),
        )
        .unwrap_or_else(|_| {
            env::panic_str("ERR_INVALID_ORCHARD_BUNDLE: failed to extract Orchard bundle")
        });
```

**File:** contracts/satoshi-bridge/tests/setup/orchard.rs (L33-34)
```rust
    // Use Coinbase bundle type which supports single output without dummy actions
    let mut builder = Builder::new(BundleType::Coinbase, Anchor::empty_tree());
```

**File:** contracts/satoshi-bridge/src/zcash_utils/refund.rs (L56-58)
```rust
/// fixed `EXPECTED_ACTIONS_NUMBER` Orchard actions.
fn shielded_refund_min_fee() -> u128 {
    zip317_min_fee(1, vec![], EXPECTED_ACTIONS_NUMBER).into_u64() as u128
```
