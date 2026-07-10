The full call chain is confirmed. Let me verify the exact state-mutation ordering before the panic to determine whether the refund request is consumed.

### Title
Publicly Reachable `env::panic_str` in `execute_refund_callback` When Orchard Bundle Is Supplied for a Transparent `refund_address` — (`contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs`)

---

### Summary

Any caller can trigger a deterministic `env::panic_str("ERR_ORCHARD_VALIDATION: ...")` inside `execute_refund_callback` by supplying a valid Orchard bundle (`chain_specific_data = Some(...)`) for a refund request whose stored `refund_address` is a Zcash transparent t-address. The panic is reachable from the public `execute_refund` entrypoint with no privileged role required. The caller loses their attached storage deposit. The refund request itself is **not** permanently destroyed (it is read-only before the panic), so the refund can still be completed by a subsequent call with `chain_specific_data = None`.

---

### Finding Description

**Call chain:**

```
execute_refund(utxo_storage_key, chain_specific_data=Some(orchard_bundle))   [public, #[payable]]
  → internal_execute_refund(...)
    → get_last_block_height_promise().then(execute_refund_callback(...))
      → load_refund_request_for_execute(...)          // READ-ONLY, no state mutation
      → PsbtWrapper::new(..., orchard_bundle, ...)    // local, no state mutation
      → check_psbt_chain_specific(&psbt, gas_fee, refund_address)
          psbt.has_orchard_bundle() == true
          → psbt.validate_orchard_bundle(refund_address /*t1...*/, chain)
              → orchard_policy::validate_orchard_bundle(orchard, "t1...", chain)
                  Address::parse("t1...", chain)  → Ok(Address::P2pkh { .. })
                  recipient_address.extract_orchard_receiver()
                      → Err("No Orchard address found")   // P2pkh arm, network.rs:255
                  propagates Err(...)
              .unwrap_or_else(|_| env::panic_str("ERR_ORCHARD_VALIDATION: ..."))
              *** PANIC ***
```

**Root cause — `network.rs:255`:** `extract_orchard_receiver` returns `Err` for any non-`Unified` address variant. [1](#0-0) 

**Panic site — `psbt_wrapper.rs:104-106`:** The `Err` is converted to a contract panic unconditionally. [2](#0-1) 

**Dispatch site — `contract_methods.rs:209-211`:** `validate_orchard_bundle` is called whenever `psbt.has_orchard_bundle()` is true, regardless of whether `target_btc_address` is a Unified Address. [3](#0-2) 

**No state is mutated before the panic.** `load_refund_request_for_execute` uses `self.data().refund_requests.get(...)` — a pure read — so the refund request survives the panic intact. [4](#0-3) 

**Public entrypoint — `bridge.rs:580-588`:** `execute_refund` is `#[payable]` with no role guard (only `#[pause]`, which allows all callers when the contract is unpaused). [5](#0-4) 

---

### Impact Explanation

| Claim in question | Actual finding |
|---|---|
| Refund permanently stuck | **Incorrect.** No state is mutated before the panic; NEAR reverts everything. The refund request remains and can be executed with `chain_specific_data = None`. |
| Caller loses attached storage deposit | **Correct.** The storage deposit attached to `execute_refund` is consumed by the failed callback. |
| Refund operator cannot finalize | **Incorrect.** Any subsequent call with `chain_specific_data = None` succeeds for a transparent t-address refund. |

The real impact is: **any caller who supplies an Orchard bundle for a t-address refund request loses their NEAR storage deposit** and the transaction fails with a panic. This is a publicly reachable panic-driven fault in a production bridge path. It does not cause theft, permanent fund loss, or a stuck refund.

This maps to the **Low** allowed impact: *"Publicly reachable invariant-violation, stuck-state, or panic-driven fault in production bridge/token paths without direct theft."*

---

### Likelihood Explanation

The precondition is straightforward: a refund request with a transparent `refund_address` must exist (a normal user flow), and the caller must supply `chain_specific_data = Some(...)`. Any unprivileged account can do this after the timelock passes. The Orchard bundle itself must be structurally valid (parseable by `extract_orchard_bundle`) to reach the panic site; an invalid bundle panics earlier with a different message. [6](#0-5) 

---

### Recommendation

In `check_psbt_chain_specific`, guard the `validate_orchard_bundle` call by first checking whether `target_btc_address` is a Unified Address with an Orchard receiver. If it is not, either reject the call with a `require!` (returning a clean error instead of a panic) or skip Orchard validation entirely. Concretely:

```rust
if psbt.has_orchard_bundle() {
    // Reject early with a clean require! instead of letting validate_orchard_bundle panic
    require!(
        Address::parse(&target_btc_address, self.internal_config().chain.clone())
            .ok()
            .and_then(|a| a.extract_orchard_receiver().ok())
            .is_some(),
        "ERR_ORCHARD_VALIDATION: refund_address has no Orchard receiver; \
         use chain_specific_data=None for a transparent refund"
    );
    psbt.validate_orchard_bundle(target_btc_address, self.internal_config().chain.clone());
}
```

This converts the panic into a clean `require!` failure, preserving the storage deposit refund semantics that NEAR provides for `require!`-style failures (the deposit is returned to the caller on a clean panic from `require!` in some SDK versions, but more importantly it gives a clear error message and avoids the confusing `ERR_ORCHARD_VALIDATION` message for a legitimate transparent-refund scenario).

---

### Proof of Concept

```rust
// Unit test sketch (no privileged role needed):
// 1. Create a refund request with refund_address = "tmD67UTsZ4iBbhCae4D43k1x8fhFNhwd4Jn" (t-address)
// 2. Fast-forward past timelock
// 3. Call execute_refund(utxo_storage_key, chain_specific_data=Some(valid_orchard_bundle))
// 4. Assert the callback panics with "ERR_ORCHARD_VALIDATION"
// 5. Assert the refund_request is still present in storage (not consumed)
// 6. Assert execute_refund(utxo_storage_key, chain_specific_data=None) succeeds afterward
```

The existing test `test_zcash_refund_transparent` confirms the transparent path works with `chain_specific_data=None`; the missing negative test is the mixed case (t-address + Orchard bundle). [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/network.rs (L242-256)
```rust
    pub fn extract_orchard_receiver(&self) -> Result<OrchardRawAddress, String> {
        match self {
            Address::Unified { address, .. } => {
                let receiver_list = address.items_as_parsed();
                for receiver in receiver_list {
                    match receiver {
                        Receiver::Orchard(bytes) => return Ok(*bytes),
                        _ => continue,
                    }
                }

                Err("Unified address missing Orchard receiver".to_string())
            }
            _ => Err("No Orchard address found".to_string()),
        }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/psbt_wrapper.rs (L96-107)
```rust
    pub fn validate_orchard_bundle(&self, expected_addr: String, chain: network::Chain) {
        orchard_policy::validate_orchard_bundle(
            self.orchard.as_ref().unwrap_or_else(|| {
                env::panic_str("ERR_NO_ORCHARD_BUNDLE: Orchard bundle is required for validation")
            }),
            &expected_addr,
            &chain,
        )
        .unwrap_or_else(|_| {
            env::panic_str("ERR_ORCHARD_VALIDATION: Orchard bundle validation failed")
        });
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/contract_methods.rs (L208-211)
```rust
        // For withdrawals with Orchard bundle, calculate the expected net amount after fees
        if psbt.has_orchard_bundle() {
            psbt.validate_orchard_bundle(target_btc_address, self.internal_config().chain.clone());
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L237-242)
```rust
        let refund_request: RefundRequest = self
            .data()
            .refund_requests
            .get(utxo_storage_key)
            .expect("Refund request not found")
            .into();
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L580-589)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn execute_refund(
        &mut self,
        utxo_storage_key: String,
        chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
        self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
    }
```

**File:** contracts/satoshi-bridge/src/zcash_utils/refund.rs (L97-124)
```rust
        let orchard_bundle = chain_specific_data.map(|c| c.orchard_bundle_bytes.0);

        // Shielded refund routes funds through the Orchard bundle (no transparent
        // output); transparent refund pays a single t-address output.
        let output = if orchard_bundle.is_some() {
            Vec::new()
        } else {
            vec![self.build_refund_output(&refund_request.refund_address, refund_amount)]
        };

        let mut psbt = PsbtWrapper::new(
            vec![outpoint],
            output,
            orchard_bundle,
            expiry_height,
            last_block_height,
            Some(refund_request.refund_address.clone()),
            self.internal_config(),
        );
        psbt.set_input_utxo(vec![deposit_output]);

        // Validate the gas fee covers the Zcash minimum and, for shielded refunds,
        // that the Orchard bundle pays out to `refund_address`.
        self.check_psbt_chain_specific(
            &psbt,
            refund_request.gas_fee,
            refund_request.refund_address.clone(),
        );
```

**File:** contracts/satoshi-bridge/tests/test_refund_zcash.rs (L347-391)
```rust
/// Transparent refund: no Orchard bundle, funds returned to a t-address.
#[tokio::test]
#[cfg(feature = "zcash")]
async fn test_zcash_refund_transparent() {
    let worker = near_workspaces::sandbox().await.unwrap();
    let context = Context::new(&worker, Some("ZcashTestnet".to_string())).await;

    // A Zcash testnet transparent address.
    let refund_taddr = "tmD67UTsZ4iBbhCae4D43k1x8fhFNhwd4Jn";
    let key = deposit_and_request_refund(&context, refund_taddr, 150_000).await;

    // chain_specific_data = None → transparent refund to the t-address.
    check!(
        print "execute_refund (transparent)"
        context.execute_refund("root", &key, None)
    );

    let pending_infos = context.get_btc_pending_infos_paged().await.unwrap();
    assert_eq!(pending_infos.len(), 1);
    let pending_keys = pending_infos.keys().cloned().collect::<Vec<_>>();
    let pending_values = pending_infos.values().cloned().collect::<Vec<_>>();
    pending_values[0].assert_pending_sign();

    check!(context.sign_btc_transaction("alice", &pending_keys[0], 0, 0));

    let pending_infos = context.get_btc_pending_infos_paged().await.unwrap();
    let pending_keys = pending_infos.keys().cloned().collect::<Vec<_>>();
    let pending_values = pending_infos.values().cloned().collect::<Vec<_>>();
    pending_values[0].assert_pending_verify();

    check!(context.verify_refund_finalize(
        "relayer",
        &pending_keys[0],
        "0000000000000c3f818b0b6374c609dd8e548a0a9e61065e942cd466c426e00d".to_string(),
        1,
        vec![],
    ));

    assert!(context
        .get_btc_pending_infos_paged()
        .await
        .unwrap()
        .is_empty());
    assert_eq!(context.ft_balance_of("alice").await.unwrap().0, 0);
}
```
