### Title
Unvalidated `refund_address` Stored in `request_refund` Causes Permanently Stuck Refund State - (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`request_refund` accepts an arbitrary `refund_address: String` from any unprivileged caller and stores it in `RefundRequest` without validating it as a well-formed BTC/ZEC address. Address parsing is deferred to `execute_refund` → `build_refund_output`, which panics on an invalid address. Once a refund request with an invalid address is stored, `execute_refund` will always panic, no second refund request can be created for the same UTXO, and the deposit is stuck until a DAO/Operator calls `reject_refund`.

---

### Finding Description

`internal_request_refund` performs three checks before storing a `RefundRequest`:

1. Sufficient attached NEAR deposit.
2. `tx_bytes` size limit.
3. If `deposit_msg.refund_address` is `Some`, the caller-supplied `refund_address` must match it. [1](#0-0) 

No check validates that `refund_address` is a parseable BTC/ZEC address for the configured chain. The value is forwarded verbatim through the light-client callback and written to storage: [2](#0-1) 

Address parsing is deferred to `build_refund_output`, called only when `execute_refund` runs: [3](#0-2) 

`Address::parse` returns `Err` for any malformed string, and `.expect("Invalid refund address")` converts that into a NEAR panic, reverting the entire `execute_refund` call. [4](#0-3) 

Once the bad request is stored, `request_refund_callback` blocks any second attempt for the same UTXO: [5](#0-4) 

The only escape is a privileged `reject_refund` call from DAO or Operator: [6](#0-5) 

---

### Impact Explanation

A deposit UTXO whose refund request carries an invalid address is permanently unexecutable. `execute_refund` panics on every invocation; no replacement request can be filed; `verify_deposit` may still succeed (the UTXO is not yet in `verified_deposit_utxo`), but if the original deposit was unfinalisable that path is also closed. The bridge is stuck for that UTXO until a privileged operator manually calls `reject_refund`. This matches the **Medium** impact class: *stuck bridge state requiring operator intervention*. [7](#0-6) 

---

### Likelihood Explanation

`request_refund` is callable by any NEAR account that attaches the required storage deposit. When `deposit_msg.refund_address` is `None` (the common case for users who did not pre-authorise a refund address), the caller supplies `refund_address` freely. An attacker who observes the victim's `deposit_msg` in NEAR transaction history (it is a plain-text parameter to `verify_deposit` or a prior `request_refund` attempt) can front-run the victim's legitimate refund request with an invalid address string, paying only the storage deposit. A user typo achieves the same result without any attacker. [8](#0-7) 

---

### Recommendation

Validate `refund_address` against the configured chain inside `internal_request_refund` (or at the top of `request_refund_callback`) before writing the `RefundRequest` to storage. Reject the request early with a descriptive error if `Address::parse` returns `Err`, rather than deferring the check to `execute_refund`.

```rust
// In request_refund_callback, before inserting:
let config = self.internal_config();
crate::network::Address::parse(&refund_address, config.chain.clone())
    .unwrap_or_else(|e| env::panic_str(&format!("Invalid refund_address: {e}")));
``` [9](#0-8) 

---

### Proof of Concept

1. Alice deposits BTC to the bridge address derived from `deposit_msg = { recipient_id: "alice.near", refund_address: None }`.
2. The deposit is never finalised (e.g., wrong amount).
3. Attacker observes Alice's `deposit_msg` in NEAR transaction history.
4. Attacker calls `request_refund(deposit_msg, refund_address="INVALID", tx_bytes, vout, proof, None)` with the required NEAR storage deposit attached.
5. Light-client verifies the BTC transaction; `request_refund_callback` stores `RefundRequest { refund_address: "INVALID", … }`.
6. Alice (or anyone) calls `execute_refund(utxo_storage_key, None)`. `build_refund_output` calls `Address::parse("INVALID", chain)` → `Err` → `panic!("Invalid refund address")`. Transaction reverts.
7. Alice tries to file a new refund request → `"Refund request already exists for this UTXO"`. Blocked.
8. Alice's BTC deposit is stuck until DAO/Operator calls `reject_refund`. [10](#0-9) [5](#0-4)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L146-159)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_request_refund(),
            "Insufficient deposit for storage"
        );
        require!(
            tx_bytes.0.len() <= MAX_REQUEST_REFUND_TX_BYTES,
            "tx_bytes too large for refund request"
        );
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
        }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L186-196)
```rust
    /// Reject a pending refund request.
    pub(crate) fn internal_reject_refund(&mut self, utxo_storage_key: String) {
        require!(
            self.data_mut()
                .refund_requests
                .remove(&utxo_storage_key)
                .is_some(),
            "Refund request not found"
        );
        Event::RefundRejected { utxo_storage_key }.emit();
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

**File:** contracts/satoshi-bridge/src/refund.rs (L496-530)
```rust
    #[private]
    pub fn request_refund_callback(
        &mut self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        gas_fee: Option<u128>,
    ) -> bool {
        let result_bytes = env::promise_result_checked(0, MAX_BOOL_RESULT)
            .expect("Call verify_transaction_inclusion failed");
        let is_valid = serde_json::from_slice::<bool>(&result_bytes)
            .expect("verify_transaction_inclusion return not bool");
        require!(is_valid, "verify_transaction_inclusion return false");

        let config = self.internal_config();
        let transaction = crate::WrappedTransaction::decode(&tx_bytes.0, &config.chain)
            .expect("Deserialization tx_bytes failed");
        let output = &transaction.output()[vout];

        // Verify that the output script matches the deposit address derived from deposit_msg
        let path = get_deposit_path(&deposit_msg);
        let deposit_address = self.generate_utxo_chain_address(&path);
        let deposit_script_pubkey = deposit_address
            .script_pubkey()
            .expect("Invalid deposit address");
        require!(
            deposit_script_pubkey == output.script_pubkey,
            "Output script_pubkey does not match deposit address"
        );

        let amount = u128::from(output.value.to_sat());
        let tx_id = transaction.compute_txid().to_string();
        let utxo_storage_key = generate_utxo_storage_key(
            tx_id,
```

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L544-568)
```rust
    pub fn reject_refund(&mut self, utxo_storage_key: String) {
        let caller = env::predecessor_account_id();
        let is_privileged = self.acl_has_role(Role::DAO.into(), caller.clone())
            || self.acl_has_role(Role::Operator.into(), caller);
        // `execute_refund` also inserts the UTXO into `verified_deposit_utxo` (to block a
        // later deposit) while keeping the request with `executed == true`. That membership
        // must NOT open the permissionless reject path, otherwise anyone could cancel an
        // in-flight refund — so only treat the UTXO as "already deposited" when the request
        // was not executed by us, i.e. a real `verify_deposit` finalized it.
        let executed = self
            .data()
            .refund_requests
            .get(&utxo_storage_key)
            .map(|r| RefundRequest::from(r).executed)
            .unwrap_or(false);
        let is_already_deposited = !executed
            && self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key);
        require!(
            is_privileged || is_already_deposited,
            "Only DAO/Operator can reject, or UTXO must be already verified via deposit"
        );
        self.internal_reject_refund(utxo_storage_key);
```
