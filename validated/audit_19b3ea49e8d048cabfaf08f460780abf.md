### Title
Orchard Bundle Action Count Strict Equality Check Rejects Valid Bundles, Blocking Zcash Withdrawals — (File: `contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs`)

---

### Summary

`extract_orchard_bundle` enforces a strict equality check requiring **exactly 1 action** in an Orchard bundle. The Orchard protocol's builder automatically pads bundles to at least 2 actions for privacy. Any padded bundle is unconditionally rejected, permanently blocking the Zcash withdrawal path for affected users.

---

### Finding Description

In `orchard_policy.rs`, the constant and check are:

```rust
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

The developer comment directly above the constant acknowledges the padding behavior:

> "The Orchard builder automatically pads bundles to meet this minimum for privacy." [3](#0-2) 

The Orchard protocol's actual minimum is **2 actions** per bundle (not 1). The builder pads to this minimum for privacy. The check `!= 1` therefore rejects every bundle the Orchard builder produces in practice, because any real bundle will have `actions().len() >= 2`.

This is the direct analog to the external report: just as `_initialMovingAverages.length == _numberOfAssets` only permits the single-mode (current-only) array and silently breaks the double-mode (current + previous) case, `bundle.actions().len() != 1` only permits a single-action bundle and silently breaks every privacy-padded bundle the protocol actually emits.

---

### Impact Explanation

Any user who initiates a ZEC withdrawal via `ft_transfer_call` on the nZEC token triggers the bridge to construct and then validate an Orchard bundle. Because the Orchard builder always pads to ≥ 2 actions, `extract_orchard_bundle` always returns an `Err`, the withdrawal call fails, and the user's nZEC remains locked in the bridge contract with no automatic recovery path. This matches the **Medium** allowed impact: *broken callback / stuck bridge state requiring operator intervention*.

---

### Likelihood Explanation

Every Zcash withdrawal that uses the Orchard shielded pool hits this code path. The Orchard builder's padding is not optional — it is enforced by the library for privacy. Any user attempting a ZEC withdrawal will encounter this failure deterministically.

---

### Recommendation

Replace the strict equality with a minimum-count guard, consistent with the comment's own description of `EXPECTED_ACTIONS_NUMBER` as a *minimum*:

```rust
if bundle.actions().len() < EXPECTED_ACTIONS_NUMBER {
    return Err(format!(
        "Orchard bundle must have at least {} action(s), got {}",
        EXPECTED_ACTIONS_NUMBER,
        bundle.actions().len()
    ));
}
```

Additionally, update `EXPECTED_ACTIONS_NUMBER` to `2` to reflect the Orchard protocol's actual minimum, and adjust the downstream single-output recovery logic (`recover_output_with_ovk(0, &ovk)`) to iterate over all actions and locate the bridge-controlled output rather than assuming index 0 is the only one. [4](#0-3) 

---

### Proof of Concept

1. User holds nZEC and calls `ft_transfer_call` on the nZEC token contract with a valid Zcash withdrawal message.
2. The bridge's `ft_on_transfer` handler accepts the transfer and begins constructing the withdrawal PSBT, including an Orchard bundle via the Orchard builder library.
3. The Orchard builder pads the bundle to ≥ 2 actions for privacy (protocol-mandated minimum).
4. The bridge calls `extract_orchard_bundle` to validate the bundle before signing/broadcasting.
5. The check `bundle.actions().len() != 1` evaluates to `true` (e.g., `2 != 1`).
6. `extract_orchard_bundle` returns `Err("Orchard bundle must have 1 actions, got 2")`.
7. The withdrawal transaction is never signed or broadcast; the user's nZEC remains locked in the bridge with no self-service recovery. [5](#0-4)

### Citations

**File:** contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs (L13-16)
```rust
/// Minimum number of actions required in an Orchard bundle per the Orchard protocol.
/// The Orchard builder automatically pads bundles to meet this minimum for privacy.
/// See: https://github.com/zcash/orchard/blob/main/src/builder.rs#L36
pub const EXPECTED_ACTIONS_NUMBER: usize = 1;
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
