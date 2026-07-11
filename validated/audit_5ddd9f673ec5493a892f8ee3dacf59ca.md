### Title
Orchard Bundle Action Count Mismatch Blocks All Standard Shielded ZEC Withdrawals — (`contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs`)

---

### Summary

`EXPECTED_ACTIONS_NUMBER = 1` enforces an exact action count of 1 on every incoming Orchard bundle, but the Orchard reference builder (`orchard` crate, `MIN_ACTIONS = 2`) always pads any bundle to **at least 2 actions** for privacy. The mismatch causes `extract_orchard_bundle` to unconditionally reject every bundle produced by a standard wallet, making shielded ZEC withdrawals impossible through the public `ft_on_transfer` path.

---

### Finding Description

**Constant and guard**

`EXPECTED_ACTIONS_NUMBER` is set to `1`: [1](#0-0) 

The guard in `extract_orchard_bundle` enforces exact equality: [2](#0-1) 

**Orchard builder reality**

The comment on lines 13–15 states *"The Orchard builder automatically pads bundles to meet this minimum for privacy"* and links to `orchard/src/builder.rs`. That file defines `MIN_ACTIONS = 2`. Any bundle built with the reference `orchard` crate — even one with a single real output — is padded to **2 actions** before serialization. A 1-action bundle cannot be produced by a standard wallet without bypassing the builder entirely.

**Call path**

`ft_on_transfer` (public, unprivileged) → `ft_on_transfer_withdraw_chain_specific` → `ft_on_transfer_callback` (#[private] callback) → `PsbtWrapper::new`: [3](#0-2) 

Inside `PsbtWrapper::new`, `extract_orchard_bundle` is called and any `Err` result causes an immediate panic: [4](#0-3) 

Because the standard builder always produces 2 actions, `bundle.actions().len() != 1` is always true, `extract_orchard_bundle` always returns `Err`, and `PsbtWrapper::new` always panics with `ERR_INVALID_ORCHARD_BUNDLE`.

---

### Impact Explanation

Every shielded ZEC withdrawal submitted through the standard `ft_on_transfer` → `ft_on_transfer_callback` path is unconditionally rejected. The shielded withdrawal feature is completely non-functional for any user relying on standard Orchard tooling.

**On fund locking**: when `ft_on_transfer_callback` panics, the NEP-141 `ft_resolve_transfer` callback in the nZEC contract observes a failed promise and, per the standard NEP-141 implementation, refunds the transferred nZEC to the sender. Funds are therefore **not permanently locked** — they are returned. The impact is a complete and permanent **denial of the shielded withdrawal feature** rather than direct fund loss.

This falls under: *Low — Publicly reachable invariant-violation, stuck-state, or panic-driven fault in production bridge/token paths without direct theft.*

---

### Likelihood Explanation

Likelihood is **high** for any user attempting a shielded withdrawal. The failure is deterministic: every standard Orchard bundle has 2 actions, the check requires exactly 1, so 100% of standard withdrawal attempts fail. No special attacker setup is required; any ordinary user triggers it.

---

### Recommendation

1. Change `EXPECTED_ACTIONS_NUMBER` to match the Orchard builder's actual minimum (`2`), or remove the exact-count check entirely and instead validate that **at least one** action is recoverable with the bridge OVK.
2. Update `recover_output_with_ovk` logic to iterate over all actions rather than hardcoding index `0`, since a 2-action bundle may place the real output at either index.
3. Correct the misleading comment: the Orchard builder pads to `MIN_ACTIONS = 2`, not 1.

---

### Proof of Concept

```rust
use orchard::builder::Builder;
use orchard::bundle::Flags;
use orchard::circuit::ProvingKey;
use orchard::keys::{FullViewingKey, SpendingKey};
use orchard::value::NoteValue;
use rand::rngs::OsRng;

let sk = SpendingKey::from_bytes([0u8; 32]).unwrap();
let fvk = FullViewingKey::from(&sk);
let recipient = fvk.address_at(0u64, orchard::keys::Scope::External);

let mut builder = Builder::new(Flags::from_parts(false, true), orchard::Anchor::empty_tree());
builder.add_output(None, recipient, NoteValue::from_raw(100_000), None).unwrap();

let pk = ProvingKey::build();
let bundle = builder.build(OsRng).unwrap().create_proof(&pk, OsRng).unwrap().prepare(OsRng, [0u8; 32]);

// The bundle has 2 actions, not 1, due to MIN_ACTIONS padding:
assert_eq!(bundle.actions().len(), 2);

// Serialise and pass to extract_orchard_bundle → returns Err because 2 != 1
// → PsbtWrapper::new panics → ft_on_transfer_callback fails → withdrawal impossible
```

The assertion `bundle.actions().len() == 2` confirms the mismatch. Any serialized bundle passed through the bridge's `ft_on_transfer` path will be rejected at the `EXPECTED_ACTIONS_NUMBER` guard. [5](#0-4) [4](#0-3) [6](#0-5)

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

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L110-137)
```rust
    pub fn ft_on_transfer_callback(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        target_btc_address: String,
        input: Vec<OutPoint>,
        output: Vec<TxOut>,
        max_gas_fee: Option<U128>,
        chain_specific_data: Option<ChainSpecificData>,
        #[callback_unwrap] last_block_height: u32,
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
