### Title
Hardcoded `EXPECTED_ACTIONS_NUMBER = 1` Rejects All Standard Zcash Wallet Orchard Bundles, Permanently Breaking Shielded Withdrawals and Refunds - (File: contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs)

---

### Summary

`EXPECTED_ACTIONS_NUMBER` is hardcoded to `1` in `orchard_policy.rs`. The Orchard protocol's standard `BundleType::Transactional` builder pads every bundle to a minimum of 2 actions for privacy (the code's own comment references `MIN_ACTIONS = 2` in the upstream orchard crate). Any Orchard bundle produced by a real Zcash wallet will have ≥2 actions and will be unconditionally rejected by the bridge. The only bundle type that produces exactly 1 action is `BundleType::Coinbase`, a non-standard type used only in the bridge's own test fixtures.

---

### Finding Description

In `contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs`, two hardcoded constants govern Orchard bundle validation:

```rust
pub const BRIDGE_OVK: [u8; 32] = [0u8; 32];
pub const EXPECTED_ACTIONS_NUMBER: usize = 1;
``` [1](#0-0) 

The `extract_orchard_bundle` function enforces an exact equality check:

```rust
if bundle.actions().len() != EXPECTED_ACTIONS_NUMBER {
    return Err(format!(
        "Orchard bundle must have {} actions, got {}",
        EXPECTED_ACTIONS_NUMBER,
        bundle.actions().len()
    ));
}
``` [2](#0-1) 

The developer's own comment acknowledges the Orchard builder pads to a minimum for privacy and links to the upstream `MIN_ACTIONS = 2` constant. The test fixture deliberately uses `BundleType::Coinbase` — a special non-standard bundle type — to bypass this padding and produce exactly 1 action:

```rust
let mut builder = Builder::new(BundleType::Coinbase, Anchor::empty_tree());
``` [3](#0-2) 

This means the bridge's test suite passes only because it uses a non-standard bundle type that no real Zcash wallet would produce. Any bundle from a standard wallet using `BundleType::Transactional` will have ≥2 actions and will be rejected.

`extract_orchard_bundle` is called from `PsbtWrapper::new` in both the withdrawal callback and the refund callback: [4](#0-3) 

The Zcash withdrawal path dispatches to `ft_on_transfer_callback` via a cross-contract promise: [5](#0-4) 

The shielded refund path calls `execute_refund_callback` which also constructs a `PsbtWrapper` with the Orchard bundle: [6](#0-5) 

---

### Impact Explanation

**Shielded withdrawals**: When a user submits a standard wallet Orchard bundle (≥2 actions), `ft_on_transfer_callback` panics with `ERR_INVALID_ORCHARD_BUNDLE`. The NEP-141 `ft_transfer_call` mechanism returns the nBTC tokens to the sender, so no tokens are permanently lost. However, the Orchard shielded withdrawal path is completely non-functional for any real wallet.

**Shielded refunds**: When a user submits a standard wallet Orchard bundle in `execute_refund`, the `execute_refund_callback` panics. The refund attempt fails and must be retried with a transparent address. The UTXO is not permanently locked (transparent refund remains available), but the shielded refund path is broken.

This is a publicly reachable fault in production bridge paths: any unprivileged Zcash user attempting a shielded Orchard withdrawal or refund with a standard wallet will hit this invariant violation.

---

### Likelihood Explanation

Likelihood is high for any user of the Zcash shielded withdrawal feature. Every standard Zcash wallet (zcashd, Zashi, YWallet, etc.) uses `BundleType::Transactional` which pads to ≥2 actions. The only way to produce a 1-action bundle is to use `BundleType::Coinbase`, which is not exposed by any standard wallet UI. The feature is effectively broken for all real users.

---

### Recommendation

1. Change the action count check from an exact equality to a minimum check (`>= 1`), and recover only the first output (index 0) as the bridge's payment output.
2. Alternatively, use `BundleType::Transactional` in the test fixtures to match real-world bundle structure, which would have caught this mismatch during testing.
3. Consider making `BRIDGE_OVK` configurable (the comment already notes this) so it can be rotated without a contract upgrade.

---

### Proof of Concept

1. User holds nBTC and calls `ft_transfer_call` on the nBTC contract targeting the bridge, with a `WithdrawMsg` containing an Orchard bundle produced by any standard Zcash wallet (e.g., Zashi). The bundle will have 2 actions (1 real + 1 dummy for privacy padding).
2. The bridge's `ft_on_transfer_withdraw_chain_specific` dispatches to `ft_on_transfer_callback`.
3. Inside the callback, `PsbtWrapper::new` calls `extract_orchard_bundle`.
4. `bundle.actions().len()` returns `2`, which `!= EXPECTED_ACTIONS_NUMBER` (1).
5. `extract_orchard_bundle` returns `Err("Orchard bundle must have 1 actions, got 2")`.
6. `PsbtWrapper::new` panics with `ERR_INVALID_ORCHARD_BUNDLE`.
7. The callback promise fails; nBTC tokens are returned to the user.
8. The shielded withdrawal is permanently blocked for this user unless they can craft a non-standard `BundleType::Coinbase` bundle manually. [7](#0-6) [2](#0-1) [8](#0-7)

### Citations

**File:** contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs (L9-16)
```rust
/// Bridge OVK used to recover outputs for policy checks.
/// Hardcoded to all zeroes for now; can be made configurable later.
pub const BRIDGE_OVK: [u8; 32] = [0u8; 32];

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

**File:** contracts/satoshi-bridge/tests/setup/orchard.rs (L32-34)
```rust
    // Build a simple output-only bundle with BRIDGE_OVK
    // Use Coinbase bundle type which supports single output without dummy actions
    let mut builder = Builder::new(BundleType::Coinbase, Anchor::empty_tree());
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

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L231-245)
```rust
        PromiseOrValue::Promise(
            self.get_last_block_height_promise().then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_FT_ON_TRANSFER_CALL_BACK)
                    .ft_on_transfer_callback(
                        sender_id,
                        amount.into(),
                        target_btc_address,
                        input,
                        output,
                        max_gas_fee,
                        chain_specific_data,
                    ),
            ),
        )
```

**File:** contracts/satoshi-bridge/src/zcash_utils/refund.rs (L107-115)
```rust
        let mut psbt = PsbtWrapper::new(
            vec![outpoint],
            output,
            orchard_bundle,
            expiry_height,
            last_block_height,
            Some(refund_request.refund_address.clone()),
            self.internal_config(),
        );
```
