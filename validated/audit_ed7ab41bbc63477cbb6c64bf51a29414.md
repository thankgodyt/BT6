### Title
Missing `refund_address` Format Validation Allows Attacker to Permanently Brick Any User's Refund Request - (File: `contracts/satoshi-bridge/src/refund.rs`)

### Summary
`request_refund` accepts and stores an arbitrary `refund_address` string without validating it against the configured Bitcoin/Zcash network. Address parsing is deferred until `execute_refund` calls `build_refund_output`. Any NEAR account can submit a refund request for any deposit UTXO with a malformed or wrong-network address, causing every subsequent `execute_refund` call to panic, permanently blocking the victim's only on-chain recovery path until a privileged DAO/Operator manually rejects the request.

### Finding Description

`request_refund` (public, no caller restriction) passes `refund_address` through to `internal_request_refund` and then to `request_refund_callback`, where it is stored verbatim in `RefundRequest` with no format check: [1](#0-0) 

Inside `request_refund_callback`, the only check involving `refund_address` is an equality comparison against `deposit_msg.refund_address` when that optional field is set. No network-aware address parsing is performed: [2](#0-1) 

The actual address validation is deferred to `build_refund_output`, called only during `execute_refund`: [3](#0-2) 

```rust
let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
    .expect("Invalid refund address");   // panics here every time
```

Because `request_refund_callback` also enforces that only one refund request can exist per UTXO: [4](#0-3) 

once the attacker's poisoned request is stored, the legitimate user cannot submit a replacement. Every call to `execute_refund` panics, and the UTXO is never added to `verified_deposit_utxo`, so the refund path is completely blocked.

### Impact Explanation

The victim's BTC is already locked in the bridge's deposit address (the whole premise of `request_refund` is that `verify_deposit` was never finalized). With the refund path bricked:

- The user cannot recover their BTC via `execute_refund` (always panics).
- The user cannot submit a new `request_refund` for the same UTXO (duplicate check blocks it).
- Recovery requires a privileged DAO/Operator to call `reject_refund`, after which the user must re-submit and pay the anti-spam deposit again.

This matches **Medium — attacker-triggered temporary locking of bridged funds** (requires operator intervention to unblock).

### Likelihood Explanation

- `request_refund` has no caller restriction; any NEAR account can invoke it for any deposit UTXO.
- The attacker only needs to observe the Bitcoin chain for unfinalized deposits (publicly visible).
- The cost is the non-refundable `required_balance_for_request_refund()` NEAR storage deposit, which is a modest economic barrier, not a security control.
- A wrong-network address (e.g., a testnet address submitted against a mainnet bridge) is syntactically plausible and passes all current checks, making the attack easy to execute without obvious detection.

### Recommendation

Validate `refund_address` against the configured chain at the point of submission, before storing the request. Add an early check in `internal_request_refund` (or at the top of `request_refund_callback`):

```rust
// Validate refund_address is parseable for the configured chain
crate::network::Address::parse(&refund_address, config.chain.clone())
    .unwrap_or_else(|e| env::panic_str(&format!("Invalid refund_address: {e}")));
```

This mirrors the validation already performed in `build_refund_output` and ensures that a stored `RefundRequest` always has an executable `refund_address`.

### Proof of Concept

1. Alice sends 0.01 BTC to her bridge deposit address but the relayer never calls `verify_deposit` (e.g., the deposit is below the minimum or the relayer is offline).
2. Attacker Eve monitors the Bitcoin chain, sees Alice's unfinalized deposit UTXO `txid@vout`.
3. Eve calls `request_refund(deposit_msg, "INVALID_OR_WRONG_NETWORK_ADDRESS", tx_bytes, vout, proof, None)` with the correct `deposit_msg` and a valid Merkle proof, attaching the required NEAR storage deposit.
4. `request_refund_callback` verifies the proof, confirms the output script matches Alice's deposit address, and stores `RefundRequest { refund_address: "INVALID_OR_WRONG_NETWORK_ADDRESS", ... }`.
5. Alice (or anyone) calls `execute_refund(utxo_storage_key, None)`. Inside `build_refund_output`, `Address::parse("INVALID_OR_WRONG_NETWORK_ADDRESS", mainnet)` panics. The call reverts.
6. Alice tries to submit her own `request_refund` — blocked: `"Refund request already exists for this UTXO"`.
7. Alice's BTC is locked until DAO/Operator calls `reject_refund`, after which Alice must re-submit and pay the anti-spam deposit again.

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

**File:** contracts/satoshi-bridge/src/refund.rs (L497-581)
```rust
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
