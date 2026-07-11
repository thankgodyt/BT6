Now I have all the code I need to trace the full path. Let me verify the exact call chain and the absence of any validation guard.

### Title
Orchard-only Unified Address as `refund_address` panics in `build_refund_output` on the transparent refund path — (`contracts/satoshi-bridge/src/refund.rs`, `contracts/satoshi-bridge/src/network.rs`)

---

### Summary

An unprivileged user can store a Zcash Unified Address containing only an Orchard receiver as `refund_address` in a refund request. When `execute_refund` is later called with `chain_specific_data = None` (transparent path), the contract panics inside `build_refund_output` via `.expect("Invalid refund script_pubkey")`. The panic reverts the transaction, leaving the refund request in storage. The refund is not permanently locked — the DAO can reject the request and the user can resubmit — but the transparent execution path is permanently broken for that request, requiring operator intervention.

---

### Finding Description

**Step 1 — Attacker stores an Orchard-only UA at `request_refund` time.**

`internal_request_refund` / `request_refund_callback` accept `refund_address: String` and store it verbatim with no format or receiver-type validation: [1](#0-0) 

**Step 2 — `execute_refund_callback` takes the transparent branch when `chain_specific_data = None`.** [2](#0-1) 

When `orchard_bundle` is `None`, `build_refund_output` is called unconditionally.

**Step 3 — `build_refund_output` panics.** [3](#0-2) 

`Address::parse` succeeds for an Orchard-only UA — it returns `Address::Unified { address, chain }` via `try_from_unified`: [4](#0-3) 

Then `script_pubkey()` iterates the receiver list looking only for `Receiver::P2pkh` and `Receiver::P2sh`. An Orchard-only UA has neither, so it falls through to: [5](#0-4) 

`Err("No receiver found in address")` is returned, and `.expect("Invalid refund script_pubkey")` panics.

---

### Impact Explanation

The panic reverts the `execute_refund_callback` transaction. The refund request remains in storage. The transparent execution path is permanently broken for that specific request — every call with `chain_specific_data = None` will panic. Recovery requires either:
- The DAO/RefundOperator calling `reject_refund` (operator intervention), after which the user can resubmit with a valid transparent address; or
- Someone constructing and providing a valid Orchard bundle via `chain_specific_data` to take the shielded path.

The "permanently stuck" framing in the question is overstated: funds are not permanently lost, and the DAO can reject the request. However, this is a publicly reachable panic-driven fault in a production refund path that requires operator intervention to resolve, matching the **Low** impact tier: *"Publicly reachable invariant-violation, stuck-state, or panic-driven fault in production bridge/token paths without direct theft."*

---

### Likelihood Explanation

Any user can trigger this by passing an Orchard-only UA string as `refund_address` when calling `request_refund`. No privilege is required. The Zcash UA encoding is well-documented and constructing an Orchard-only UA is straightforward. The trigger condition (`chain_specific_data = None`) is the default transparent-refund call.

---

### Recommendation

Validate `refund_address` at `request_refund_callback` time for Zcash chains: parse it with `Address::parse` and immediately call `script_pubkey()`, rejecting the request if it returns an error. This moves the failure to the request-submission step (where it can be surfaced as a clean error) rather than the execution step (where it panics).

---

### Proof of Concept

```rust
// 1. Construct a Zcash Unified Address with only an Orchard receiver.
//    (Use any standard zcash_address library to encode one.)
let orchard_only_ua = "u1<...orchard-only-ua-string...>";

// 2. Submit a refund request with this address (unprivileged call).
contract.request_refund(deposit_msg, orchard_only_ua.to_string(), tx_bytes, vout, proof, None);

// 3. Wait for timelock to pass, then call execute_refund with chain_specific_data = None.
contract.execute_refund(utxo_storage_key, None);
// → execute_refund_callback fires
// → orchard_bundle = None → build_refund_output is called
// → Address::parse succeeds, returns Address::Unified
// → script_pubkey() returns Err("No receiver found in address")
// → .expect("Invalid refund script_pubkey") panics
// → transaction reverts; refund request remains stuck, requiring DAO intervention
```

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L294-300)
```rust
    pub(crate) fn build_refund_output(&self, refund_address: &str, refund_amount: u128) -> TxOut {
        let config = self.internal_config();
        let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
            .expect("Invalid refund address");
        let refund_script_pubkey = refund_addr
            .script_pubkey()
            .expect("Invalid refund script_pubkey");
```

**File:** contracts/satoshi-bridge/src/refund.rs (L564-574)
```rust
        let refund_request = RefundRequest {
            deposit_msg_json: serde_json::to_string(&deposit_msg).unwrap(),
            utxo_storage_key: utxo_storage_key.clone(),
            tx_bytes,
            vout,
            amount,
            refund_address,
            gas_fee: resolved_gas_fee,
            created_at_sec: nano_to_sec(env::block_timestamp()),
            executed: false,
        };
```

**File:** contracts/satoshi-bridge/src/zcash_utils/refund.rs (L97-105)
```rust
        let orchard_bundle = chain_specific_data.map(|c| c.orchard_bundle_bytes.0);

        // Shielded refund routes funds through the Orchard bundle (no transparent
        // output); transparent refund pays a single t-address output.
        let output = if orchard_bundle.is_some() {
            Vec::new()
        } else {
            vec![self.build_refund_output(&refund_request.refund_address, refund_amount)]
        };
```

**File:** contracts/satoshi-bridge/src/network.rs (L137-147)
```rust
    fn try_from_unified(
        net: zcash_protocol::consensus::NetworkType,
        data: zcash_address::unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        let chain = zcash_chain_from_network(net)?;

        Ok(Self::Unified {
            address: data,
            chain,
        })
    }
```

**File:** contracts/satoshi-bridge/src/network.rs (L214-237)
```rust
            Address::Unified { address, .. } => {
                let receiver_list = address.items_as_parsed();
                for receiver in receiver_list {
                    match receiver {
                        Receiver::P2pkh(data) => {
                            return Ok(bitcoin::ScriptBuf::new_p2pkh(
                                &PubkeyHash::from_slice(&data[..]).map_err(|err| {
                                    format!("Error on parsing Pubkey Hash: {err:?}").to_string()
                                })?,
                            ))
                        }
                        Receiver::P2sh(data) => {
                            return Ok(bitcoin::ScriptBuf::new_p2sh(
                                &ScriptHash::from_slice(&data[..]).map_err(|err| {
                                    format!("Error on parsing Script Hash: {err:?}").to_string()
                                })?,
                            ))
                        }
                        _ => {}
                    }
                }

                Err("No receiver found in address".to_string())
            }
```
