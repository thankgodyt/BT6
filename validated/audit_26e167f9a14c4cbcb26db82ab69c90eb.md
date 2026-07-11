Now I have all the information needed to make a determination. Let me trace the exact path.

### Title
Shielded-Only Unified Address as `refund_address` Causes Panic in `execute_refund_callback` — (`contracts/satoshi-bridge/src/network.rs`, `refund.rs`, `zcash_utils/refund.rs`)

---

### Summary

`request_refund` stores `refund_address` as a raw string with no validation that the address contains a transparent receiver. When `execute_refund` is later called without `chain_specific_data` (transparent path), `execute_refund_callback` calls `build_refund_output`, which calls `Address::parse` (succeeds for any valid UA) and then `.script_pubkey().expect("Invalid refund script_pubkey")`. For a Unified Address containing only an Orchard receiver, `script_pubkey()` returns `Err("No receiver found in address")`, and the `.expect` panics, aborting the callback.

---

### Finding Description

**Step 1 — No address validation at request time.**

`internal_request_refund` and `request_refund_callback` store `refund_address` verbatim: [1](#0-0) 

There is no call to `Address::parse` or any check that the address contains a transparent receiver. A Zcash Unified Address with only an Orchard receiver is accepted.

**Step 2 — `execute_refund` is publicly callable after the timelock.**

`resolve_execute_refund_timelock` explicitly handles non-privileged callers by returning `config.unsafe_refund_timelock_sec` for them: [2](#0-1) 

The `execute_refund` method itself carries only `#[payable]` and `#[pause]` guards — no per-method `#[trusted_relayer]`: [3](#0-2) 

**Step 3 — Transparent path calls `build_refund_output` when `chain_specific_data` is `None`.** [4](#0-3) 

**Step 4 — `build_refund_output` panics on a shielded-only UA.** [5](#0-4) 

`Address::parse` on a valid Zcash UA always succeeds and returns `Address::Unified`: [6](#0-5) 

`script_pubkey()` on `Address::Unified` iterates receivers and returns `Err` if no `P2pkh` or `P2sh` receiver is found: [7](#0-6) 

The `.expect("Invalid refund script_pubkey")` at line 300 of `refund.rs` then panics, aborting the callback and rolling back all state changes made within it.

---

### Impact Explanation

The panic aborts `execute_refund_callback`. Because NEAR rolls back state changes on panic, the refund request remains in storage. The refund is **not permanently stuck**: the DAO/Operator can either (a) reject the request via `reject_refund` (allowing the user to resubmit with a transparent address), or (b) call `execute_refund` with a valid `chain_specific_data` Orchard bundle to route the refund through the shielded path. No funds are permanently lost, but the transparent refund path is broken for this request and requires operator intervention to resolve.

Impact: **Low** — publicly reachable panic/stuck-state in a production bridge path without direct theft.

---

### Likelihood Explanation

Any caller can submit a `request_refund` with a shielded-only UA as `refund_address` (no format validation). After `unsafe_refund_timelock_sec` elapses (and if the DAO/Operator does not reject the request), any caller can trigger the panic by calling `execute_refund` with `chain_specific_data = None`. The path is concrete and locally testable.

---

### Recommendation

1. **Validate `refund_address` at request time.** In `request_refund_callback`, call `Address::parse` and, for `Address::Unified`, call `script_pubkey()` to confirm a transparent receiver exists before storing the request. Reject requests whose address cannot produce a transparent output.

2. **Replace `.expect()` with graceful error handling** in `build_refund_output` so that a missing transparent receiver returns a contract-level error rather than a panic.

---

### Proof of Concept

```
1. Deploy bridge configured for ZcashTestnet.
2. Deposit ZEC to a bridge address; obtain tx_bytes, vout, proof.
3. Construct a Zcash Unified Address containing ONLY an Orchard receiver
   (no t-addr component) — call it UA_ORCHARD_ONLY.
4. Call request_refund(deposit_msg, UA_ORCHARD_ONLY, tx_bytes, vout, proof, None)
   with sufficient attached deposit.
5. Wait for unsafe_refund_timelock_sec to elapse.
6. Call execute_refund(utxo_storage_key, None)  // chain_specific_data = None
7. Observe: execute_refund_callback panics with
   "Invalid refund script_pubkey: No receiver found in address".
8. Assert: refund request still present in contract state; funds require
   operator intervention to recover.
```

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L201-228)
```rust
    pub(crate) fn resolve_execute_refund_timelock(&self, utxo_storage_key: &str) -> u64 {
        require!(
            env::attached_deposit() >= self.required_balance_for_execute_refund(),
            "Insufficient deposit for storage"
        );
        let caller = env::predecessor_account_id();
        let is_privileged =
            self.acl_has_any_role(vec![Role::DAO.into(), Role::RefundOperator.into()], caller);
        let refund_request: RefundRequest = self
            .data()
            .refund_requests
            .get(utxo_storage_key)
            .expect("Refund request not found")
            .into();
        let config = self.internal_config();
        if refund_request.deposit_msg().refund_address.is_some() {
            // Pre-authorized refund address: privileged users can fast-track.
            if is_privileged {
                0
            } else {
                config.refund_timelock_sec
            }
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L294-308)
```rust
    pub(crate) fn build_refund_output(&self, refund_address: &str, refund_amount: u128) -> TxOut {
        let config = self.internal_config();
        let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
            .expect("Invalid refund address");
        let refund_script_pubkey = refund_addr
            .script_pubkey()
            .expect("Invalid refund script_pubkey");
        TxOut {
            value: Amount::from_sat(
                u64::try_from(refund_amount)
                    .unwrap_or_else(|_| env::panic_str("Refund amount overflow")),
            ),
            script_pubkey: refund_script_pubkey,
        }
    }
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
