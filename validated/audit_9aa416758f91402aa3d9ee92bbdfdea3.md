### Title
Orchard-Only Unified Zcash Address Causes Permanent Panic in Refund Execution — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`build_refund_output` in `refund.rs` calls `script_pubkey().expect("Invalid refund script_pubkey")` on a parsed Zcash address. For a Unified Zcash address that contains **only** an Orchard receiver (no transparent P2PKH or P2SH receiver), `script_pubkey()` returns `Err("No receiver found in address")`, causing the `.expect()` to panic. Because `refund_address` is accepted as a raw `String` and stored without format validation at request time, any unprivileged user can submit a refund request with such an address, permanently blocking `execute_refund` for that UTXO.

---

### Finding Description

**Step 1 — `request_refund` stores the address without validation.**

`internal_request_refund` in `refund.rs` accepts `refund_address: String` and stores it verbatim in `RefundRequest.refund_address` with no check that the address can produce a valid `script_pubkey`. [1](#0-0) 

**Step 2 — `Address::parse` successfully accepts Orchard-only Unified addresses.**

`Address::parse` in `network.rs` routes Zcash addresses through `ZcashAddress::try_from_encoded` → `convert_if_network`, which calls `try_from_unified` and returns `Address::Unified { address, chain }` for any valid Unified address — including one that carries only an Orchard receiver. [2](#0-1) 

**Step 3 — `script_pubkey()` silently skips Orchard/Sapling receivers and returns `Err`.**

The `script_pubkey()` implementation for `Address::Unified` iterates the receiver list and only handles `Receiver::P2pkh` and `Receiver::P2sh`. All other receiver types (including `Receiver::Orchard`) fall through the `_ => {}` arm. If no transparent receiver is found, the function returns `Err("No receiver found in address")`. [3](#0-2) 

**Step 4 — `build_refund_output` panics on that `Err`.**

`build_refund_output` calls `script_pubkey().expect("Invalid refund script_pubkey")`. For an Orchard-only Unified address the `.expect()` panics, aborting the `execute_refund` transaction before any state is written. [4](#0-3) 

**Contrast with the withdrawal path.** `check_withdraw_psbt` in `psbt.rs` explicitly handles the shielded-only case by allowing `target_address_script_pubkey` to be `None`. The refund path has no equivalent guard. [5](#0-4) 

---

### Impact Explanation

Every call to `execute_refund` for the affected UTXO panics and reverts. The `RefundRequest` remains in storage but can never be executed. If the user pre-authorized the Orchard-only address via `deposit_msg.refund_address`, the `request_refund` check (`msg_refund_address == &refund_address`) prevents them from submitting a new request with a different address. The deposit UTXO is permanently unrecoverable without operator intervention (DAO rejection of the stuck request), and even after rejection the user cannot re-submit because the `deposit_msg.refund_address` binding persists.

This matches the **Medium** allowed impact: *broken callback rollback / stuck bridge state requiring operator intervention*, and edges toward **Critical** (*permanent loss of user funds*) when the refund address was pre-committed in `deposit_msg`.

---

### Likelihood Explanation

Orchard-only Unified Zcash addresses are valid, wallet-generated addresses. A user who holds ZEC in a shielded-only wallet and sets `deposit_msg.refund_address` to their Orchard-only Unified address triggers this path without any privileged access. The entry point (`request_refund`) is fully public and payable. [6](#0-5) 

---

### Recommendation

Validate the refund address at request time inside `request_refund_callback`: attempt `Address::parse(...)` followed by `script_pubkey()` and reject the request if either fails. This mirrors the validation already implicit in `build_refund_output` but surfaces the error early, before the address is persisted, so the user can correct it.

Alternatively, extend `build_refund_output` (and the Zcash-specific refund path) to handle Orchard-only Unified addresses by routing them through the shielded bundle rather than a transparent `TxOut`.

---

### Proof of Concept

1. User deposits ZEC to the bridge with `deposit_msg.refund_address = Some("u1<orchard-only-unified-addr>")`.
2. The deposit is never finalized (relayer down, invalid proof, etc.).
3. User calls `request_refund(deposit_msg, "u1<orchard-only-unified-addr>", tx_bytes, vout, proof, None)`.
4. `request_refund_callback` stores the `RefundRequest` with `refund_address = "u1<orchard-only-unified-addr>"` — no address validation occurs.
5. After the timelock, anyone calls `execute_refund(utxo_storage_key, None)`.
6. `build_refund_output("u1<orchard-only-unified-addr>", refund_amount)` is invoked.
7. `Address::parse(...)` succeeds → `Address::Unified { ... }`.
8. `script_pubkey()` iterates receivers, finds only `Receiver::Orchard`, falls through `_ => {}`, returns `Err("No receiver found in address")`.
9. `.expect("Invalid refund script_pubkey")` panics → transaction reverts.
10. The user cannot re-submit `request_refund` with a different address because `deposit_msg.refund_address` is bound to the Orchard-only address. Funds are permanently locked. [3](#0-2) [4](#0-3) [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L137-159)
```rust
    pub(crate) fn internal_request_refund(
        &self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
        gas_fee: Option<u128>,
    ) -> Promise {
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

**File:** contracts/satoshi-bridge/src/refund.rs (L496-581)
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
            u32::try_from(vout).unwrap_or_else(|_| env::panic_str("vout overflow")),
        );

        // Double-check not finalized (could have been verified between request and callback)
        require!(
            !self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key),
            "UTXO already verified via deposit"
        );

        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );

        let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
        require!(
            resolved_gas_fee < amount,
            "Gas fee must be less than deposit amount"
        );

        Event::RefundRequested {
            deposit_msg: deposit_msg.clone(),
            utxo_storage_key: utxo_storage_key.clone(),
            amount: amount.into(),
            refund_address: refund_address.clone(),
            gas_fee: resolved_gas_fee.into(),
        }
        .emit();

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

        true
    }
```

**File:** contracts/satoshi-bridge/src/network.rs (L152-166)
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

**File:** contracts/satoshi-bridge/src/psbt.rs (L184-196)
```rust
        if !psbt.get_output().is_empty() {
            // `None` when the target is a shielded-only Zcash unified address (no transparent
            // receiver): the user is paid via the Orchard bundle and every transparent output
            // is change, so there is nothing for a transparent output to match against.
            let target_address_script_pubkey = self
                .internal_config()
                .target_script_pubkey(&target_btc_address);

            psbt.get_output().iter().for_each(|output| {
                let output_value = output.value.to_sat() as u128;
                total_output_amount += output_value;
                if target_address_script_pubkey.as_ref() == Some(&output.script_pubkey) {
                    actual_received_amounts.push(output_value);
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L508-535)
```rust
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
