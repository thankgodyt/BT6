Now I have all the information needed to make a determination. Let me trace the full path precisely.

**Key observations:**

1. `request_refund` is in a `#[trusted_relayer]` impl block (bridge.rs line 480), but the method itself has only `#[payable]` and `#[pause(except(roles(Role::DAO)))]` — no individual `#[trusted_relayer]` attribute. Methods that are actually gated (e.g., `verify_refund_finalize` at line 602, `remove_refund_pending_tx_id` at line 622) carry the attribute individually. The impl-block-level `#[trusted_relayer]` generates management helpers, not per-method guards. So `request_refund` is publicly callable.

2. In `internal_request_refund` (refund.rs lines 154–158), if `deposit_msg.refund_address` is `Some(x)`, it only checks that `x == refund_address`. No BTC address format validation occurs.

3. `request_refund_callback` (refund.rs lines 564–578) stores the `RefundRequest` with `refund_address` verbatim — still no format validation.

4. `execute_refund` → `internal_execute_refund` → `build_refund_output` (refund.rs lines 296–297) calls `Address::parse(refund_address, ...).expect("Invalid refund address")`, which panics on an invalid address string.

5. The UTXO is only added to `verified_deposit_utxo` inside `finalize_refund_with_psbt` (refund.rs lines 378–380), which is never reached because the panic occurs before it. So the question's claim that `verify_deposit` is blocked is inaccurate — but the core stuck-state is real.

---

### Title
Unprivileged user can store a `RefundRequest` with an invalid `refund_address`, permanently bricking `execute_refund` for that UTXO — (`contracts/satoshi-bridge/src/refund.rs`)

### Summary
`request_refund` accepts any string as `refund_address` without validating it as a well-formed BTC address. The value is stored verbatim in `RefundRequest`. When `execute_refund` is later called, `build_refund_output` calls `Address::parse` on the stored string and panics on failure. The refund request becomes permanently unexecutable, locking the user's deposited BTC until DAO intervention.

### Finding Description
`DepositMsg.refund_address` is an `Option<String>` with no format constraint. [1](#0-0) 

`internal_request_refund` only checks that the caller-supplied `refund_address` matches `deposit_msg.refund_address` when the latter is `Some`; it performs no BTC address format validation. [2](#0-1) 

`request_refund_callback` stores the `RefundRequest` with the unvalidated string directly. [3](#0-2) 

Later, `build_refund_output` calls `Address::parse` and panics via `.expect` if the string is not a valid address for the configured chain. [4](#0-3) 

`Address::parse` returns `Err(String)` for any malformed input. [5](#0-4) 

### Impact Explanation
Every call to `execute_refund` for the affected UTXO panics. The refund request is permanently stuck in storage. The deposited BTC sits on the bridge's MPC-controlled deposit address and cannot be returned to the user without DAO intervention (calling `reject_refund` to remove the request, then using privileged `active_utxo_management` to sweep the UTXO). This violates the invariant that a stored `RefundRequest` is always executable. The impact is a stuck-state / panic-driven fault matching the Low allowed scope.

Note: the question's claim that `verified_deposit_utxo` is set (blocking `verify_deposit`) is inaccurate — that insertion happens inside `finalize_refund_with_psbt` [6](#0-5) 
which is never reached because the panic occurs earlier in `build_refund_output`. However, the core stuck-state impact is confirmed.

### Likelihood Explanation
`request_refund` is publicly callable (no `#[trusted_relayer]` on the method itself, only `#[payable]` and `#[pause]`). [7](#0-6) 

Any user who has sent BTC to a deposit address can trigger this by including an invalid string in `deposit_msg.refund_address`. The only prerequisite is a real on-chain BTC deposit and a valid light-client proof — both are normal user actions. The attack is deterministic and requires no privileged access.

### Recommendation
Validate `refund_address` as a well-formed BTC address at the point it is first accepted — either in `internal_request_refund` before the light-client call, or at the start of `request_refund_callback` before storing the `RefundRequest`. Reject the request with a clear error rather than storing an address that will cause a panic at execution time.

### Proof of Concept
1. Construct `deposit_msg = { recipient_id: "alice.near", refund_address: Some("not_a_btc_address") }`.
2. Derive the deposit address via `get_deposit_path(&deposit_msg)` and send BTC to it on-chain.
3. Call `request_refund(deposit_msg, "not_a_btc_address", tx_bytes, vout, proof, None)` with sufficient attached NEAR and a valid light-client proof.
4. `internal_request_refund` passes the equality check (both sides are `"not_a_btc_address"`); the light-client call succeeds; `request_refund_callback` stores the `RefundRequest`.
5. After the timelock, call `execute_refund(utxo_storage_key, None)`.
6. Observe the contract panics with `"Invalid refund address"` inside `build_refund_output`.
7. Repeat step 5 indefinitely — the result is always a panic. The BTC is permanently locked.

### Citations

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L26-27)
```rust
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_address: Option<String>,
```

**File:** contracts/satoshi-bridge/src/refund.rs (L154-158)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L294-298)
```rust
    pub(crate) fn build_refund_output(&self, refund_address: &str, refund_amount: u128) -> TxOut {
        let config = self.internal_config();
        let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
            .expect("Invalid refund address");
        let refund_script_pubkey = refund_addr
```

**File:** contracts/satoshi-bridge/src/refund.rs (L377-380)
```rust
        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());
```

**File:** contracts/satoshi-bridge/src/refund.rs (L564-578)
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

        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());
```

**File:** contracts/satoshi-bridge/src/network.rs (L152-206)
```rust
    pub fn parse(address: &str, chain: Chain) -> Result<Self, String> {
        if chain == Chain::ZcashMainnet || chain == Chain::ZcashTestnet {
            let addr = ZcashAddress::try_from_encoded(address)
                .map_err(|e| format!("Error on parsing ZCash Address: {e}"))?;

            let network = match chain {
                Chain::ZcashMainnet => zcash_protocol::consensus::NetworkType::Main,
                Chain::ZcashTestnet => zcash_protocol::consensus::NetworkType::Test,
                _ => unreachable!(),
            };

            return addr
                .convert_if_network::<Self>(network)
                .map_err(|e| e.to_string());
        }

        if let Some(hrp) = get_segwit_hrp(&chain) {
            if let Ok((decoded_hrp, witness_version, data)) = bech32::segwit::decode(address) {
                let expected_hrp =
                    Hrp::parse(hrp).map_err(|e| format!("Invalid expected HRP '{hrp}': {e}"))?;
                if expected_hrp != decoded_hrp {
                    return Err(format!(
                        "Bech32 HRP mismatch: expected '{hrp}', got '{decoded_hrp}'"
                    ));
                }

                let version =
                    WitnessVersion::try_from(witness_version).map_err(|err| format!("{err:?}"))?;
                let program = WitnessProgram::new(version, &data).map_err(|err| {
                    format!("bech32 guarantees valid program length for witness: {err:?}")
                })?;

                return Ok(Address::Segwit { program, chain });
            }
        }

        let data = bitcoin::base58::decode_check(address)
            .map_err(|e| format!("Base58 decode error: {e}"))?;

        let prefix = get_pubkey_address_prefix(&chain);
        if data.starts_with(&prefix) {
            let hash = PubkeyHash::from_slice(&data[prefix.len()..])
                .map_err(|e| format!("Invalid pubkey hash: {e}"))?;
            return Ok(Address::P2pkh { hash, chain });
        }

        let prefix = get_script_address_prefix(&chain);
        if data.starts_with(&prefix) {
            let hash = ScriptHash::from_slice(&data[prefix.len()..])
                .map_err(|e| format!("Invalid script hash: {e}"))?;
            return Ok(Address::P2sh { hash, chain });
        }

        Err("Unknown address format or unsupported chain".to_string())
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L507-535)
```rust
    #[allow(clippy::too_many_arguments)]
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn request_refund(
        &mut self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
        gas_fee: Option<U128>,
    ) -> Promise {
        if gas_fee.is_some() {
            let caller = env::predecessor_account_id();
            require!(
                self.acl_has_role(Role::DAO.into(), caller.clone())
                    || self.acl_has_role(Role::Operator.into(), caller),
                "Only DAO or Operator can specify custom gas_fee"
            );
        }
        self.internal_request_refund(
            deposit_msg,
            refund_address,
            tx_bytes,
            vout,
            proof,
            gas_fee.map(|v| v.0),
        )
    }
```
