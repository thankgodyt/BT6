### Title
Off-by-One in Orchard Bundle Action Count Validation Blocks All Zcash Shielded Withdrawals - (File: contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs)

### Summary
`EXPECTED_ACTIONS_NUMBER` is set to `1`, but the Orchard protocol requires a minimum of **2** actions per bundle (the builder pads to `MIN_ACTIONS = 2` for privacy). The strict equality check `bundle.actions().len() != EXPECTED_ACTIONS_NUMBER` therefore rejects every legitimately constructed Orchard bundle, causing a panic in `PsbtWrapper::new()` and permanently breaking all Zcash shielded withdrawals.

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

The developer comment itself links to `zcash/orchard/blob/main/src/builder.rs#L36`, where `MIN_ACTIONS = 2` is defined. The Orchard builder always pads bundles to at least 2 actions for privacy (to prevent distinguishing 1-note from 2-note transactions). The constant is named and described as a *minimum*, but the check enforces it as an *exact count*. Any real Orchard bundle produced by the standard builder will have `actions().len() == 2`, which fails `!= 1`, causing `extract_orchard_bundle` to return `Err`.

This error propagates into `PsbtWrapper::new()`:

```rust
let orchard = orchard_policy::extract_orchard_bundle(
    orchard_bundle_bytes,
    proof_size_enforcement(get_branch_id(current_height, config)),
)
.unwrap_or_else(|_| {
    env::panic_str("ERR_INVALID_ORCHARD_BUNDLE: failed to extract Orchard bundle")
});
``` [3](#0-2) 

The contract panics unconditionally for every Zcash shielded withdrawal attempt.

### Impact Explanation
Every user who attempts a Zcash shielded withdrawal (to a unified address carrying an Orchard receiver) triggers a panic inside `ft_on_transfer`. The NEAR runtime reverts the call and `ft_resolve_transfer` returns the nZEC tokens to the user, so funds are not permanently lost. However, the entire Zcash shielded withdrawal path is permanently broken: no user can ever successfully complete a shielded withdrawal. This is a publicly reachable panic-driven fault in a core production bridge path.

**Allowed impact matched:** *Low — Publicly reachable invariant-violation, stuck-state, or panic-driven fault in production bridge/token paths without direct theft.*

### Likelihood Explanation
Any unprivileged user who submits a Zcash shielded withdrawal with a standard Orchard bundle (the only kind the Orchard builder produces) will trigger this panic. Likelihood is **high** for anyone using the Zcash shielded withdrawal feature.

### Recommendation
Change the equality check to accept bundles with at least `MIN_ACTIONS` (2) actions, and extract the single user-facing output from the bundle rather than assuming exactly 1 action exists:

```rust
pub const MIN_ACTIONS_NUMBER: usize = 2; // Orchard protocol minimum

if bundle.actions().len() < MIN_ACTIONS_NUMBER {
    return Err(format!(
        "Orchard bundle must have at least {} actions, got {}",
        MIN_ACTIONS_NUMBER,
        bundle.actions().len()
    ));
}
```

Then recover the user output from action index `0` as before (the first action is the real payment; remaining actions are privacy padding).

### Proof of Concept
1. User calls `ft_transfer_call` on the nZEC contract with a `Withdraw` message targeting a shielded Zcash unified address.
2. The bridge's `ft_on_transfer` constructs a `PsbtWrapper` via `PsbtWrapper::new(...)`, passing the Orchard bundle bytes.
3. `extract_orchard_bundle` reads the bundle; the standard Orchard builder has produced a bundle with 2 actions (`MIN_ACTIONS = 2`).
4. `bundle.actions().len() != 1` evaluates to `true`; `extract_orchard_bundle` returns `Err(...)`.
5. `unwrap_or_else` calls `env::panic_str("ERR_INVALID_ORCHARD_BUNDLE: ...")`.
6. The NEAR transaction reverts; `ft_resolve_transfer` returns nZEC to the user.
7. The shielded withdrawal is permanently impossible for all users.

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
