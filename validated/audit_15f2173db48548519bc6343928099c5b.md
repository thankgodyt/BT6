### Title
Missing `refund_address` Validation in `request_refund` Enables Stuck Refund State Requiring Operator Intervention — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary
`request_refund_callback` validates the deposit output's script against the expected deposit address, but stores the caller-supplied `refund_address` without any format validation. Later, `execute_refund` → `build_refund_output` calls `Address::parse(...).expect("Invalid refund address")`, which panics on an invalid address. Because `request_refund_callback` blocks duplicate requests for the same UTXO, a single griefing call with an invalid `refund_address` permanently blocks `execute_refund` for that UTXO until a DAO/Operator calls `reject_refund`.

---

### Finding Description

In `request_refund_callback`, the deposit output is carefully validated against the expected deposit address: [1](#0-0) 

However, the `refund_address` supplied by the caller is stored directly into `RefundRequest` with no format or chain-compatibility check: [2](#0-1) 

Later, `build_refund_output` parses the stored address with `.expect()`: [3](#0-2) 

If the address is invalid for the configured chain, every call to `execute_refund` panics at this point. The refund request remains in storage, and the duplicate-request guard in `request_refund_callback` prevents any other caller from submitting a valid replacement: [4](#0-3) 

The `deposit_msg` needed to construct a valid refund request is publicly emitted as an on-chain event by `get_user_deposit_address`: [5](#0-4) 

`request_refund` is a public, payable function (no `#[trusted_relayer]` guard on the method itself), so any account that pays the anti-spam deposit can submit a refund request for any unverified UTXO: [6](#0-5) 

---

### Impact Explanation

Once a refund request with an invalid `refund_address` is stored, `execute_refund` always panics. The victim's deposit UTXO is locked inside the stuck `RefundRequest`. Only a DAO or Operator calling `reject_refund` can clear it. This is a stuck bridge state requiring operator intervention, matching the **Medium** allowed impact. [7](#0-6) 

---

### Likelihood Explanation

`request_refund` is publicly callable by any account willing to pay the anti-spam deposit. The `deposit_msg` of any pending deposit is observable on-chain via the `LogDepositAddress` event. An attacker can front-run a victim's refund attempt (or preemptively submit one) with a syntactically invalid or wrong-network `refund_address` at the cost of the anti-spam fee, permanently blocking `execute_refund` for that UTXO until operator intervention.

---

### Recommendation

Validate `refund_address` against the chain's address format inside `request_refund_callback` (before storing the `RefundRequest`), mirroring how the deposit output's `script_pubkey` is already validated. Reject the callback with a `require!` failure if `Address::parse(refund_address, config.chain)` returns an error, so the anti-spam deposit is not consumed for an unexecutable request.

---

### Proof of Concept

1. Victim calls `get_user_deposit_address(deposit_msg)` — emits `LogDepositAddress` event with the full `deposit_msg`.
2. Victim sends BTC to the derived deposit address.
3. Attacker observes the event and the BTC transaction on-chain.
4. Attacker calls `request_refund(deposit_msg, "INVALID_ADDRESS", tx_bytes, vout, proof, None)` with the required anti-spam deposit attached.
5. Light client verifies the transaction inclusion; `request_refund_callback` validates the deposit output but stores `"INVALID_ADDRESS"` as `refund_address` without validation.
6. Anyone calls `execute_refund(utxo_storage_key, None)` — `build_refund_output` calls `Address::parse("INVALID_ADDRESS", chain).expect(...)` and panics.
7. The refund request remains in storage; the duplicate-request guard blocks the victim from submitting a valid replacement.
8. DAO/Operator must call `reject_refund(utxo_storage_key)` to unblock the UTXO. [8](#0-7) [9](#0-8)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L137-184)
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

        let transaction =
            crate::WrappedTransaction::decode(&tx_bytes.0, &self.internal_config().chain)
                .expect("Deserialization tx_bytes failed");
        let tx_id = transaction.compute_txid().to_string();

        let config = self.internal_config();
        let deposit_amount = u128::from(transaction.output()[vout].value.to_sat());
        let confirmations = self.get_confirmations(config, deposit_amount);

        self.verify_transaction_inclusion_promise(
            config.btc_light_client_account_id.clone(),
            tx_id,
            proof.tx_block_blockhash,
            proof.tx_index,
            proof.merkle_proof,
            Some((proof.coinbase_tx_id, proof.coinbase_merkle_proof)),
            confirmations,
        )
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_FOR_REQUEST_REFUND_CALLBACK)
                .request_refund_callback(deposit_msg, refund_address, tx_bytes, vout, gas_fee),
        )
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

**File:** contracts/satoshi-bridge/src/refund.rs (L517-525)
```rust
        let path = get_deposit_path(&deposit_msg);
        let deposit_address = self.generate_utxo_chain_address(&path);
        let deposit_script_pubkey = deposit_address
            .script_pubkey()
            .expect("Invalid deposit address");
        require!(
            deposit_script_pubkey == output.script_pubkey,
            "Output script_pubkey does not match deposit address"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L564-575)
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L462-472)
```rust
    pub fn get_user_deposit_address(&self, deposit_msg: DepositMsg) -> String {
        let path = get_deposit_path(&deposit_msg);
        let deposit_address = self.generate_utxo_chain_address(&path).to_string();
        Event::LogDepositAddress {
            deposit_msg,
            path,
            deposit_address: deposit_address.clone(),
        }
        .emit();
        deposit_address
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
