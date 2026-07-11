Based on my analysis of the production code, here is my assessment:

---

### Title
Concurrent `request_refund` Calls for Same UTXO Cause Permanent Loss of Anti-Spam Deposit — (`contracts/satoshi-bridge/src/api/bridge.rs`, `contracts/satoshi-bridge/src/refund.rs`)

### Summary
When two `request_refund` calls targeting the same UTXO are submitted before either callback executes, both light-client verifications succeed. The first callback stores the refund request; the second callback panics via `require!` with "Refund request already exists for this UTXO". Because the 2 NEAR anti-spam deposit was transferred to the contract when the outer call succeeded (returned a Promise), and the callback has no deposit-refund logic, the second caller's deposit is permanently consumed with no stored refund request.

### Finding Description

`request_refund` is `#[payable]` and lives in a `#[trusted_relayer]` impl block but carries **no individual** `#[trusted_relayer]` attribute on the function itself: [1](#0-0) 

Compare with `verify_refund_finalize` and `remove_refund_pending_tx_id` in the same impl block, which do carry the individual attribute: [2](#0-1) 

This makes `request_refund` publicly callable. `internal_request_refund` checks the deposit and returns a Promise (success); the 2 NEAR deposit is transferred to the contract at that point: [3](#0-2) 

The callback then performs a duplicate check: [4](#0-3) 

The code comment at line 543 explicitly acknowledges the race: *"another request_refund could have landed between our check and callback"*. However, the `require!` macro panics without returning the attached deposit. There is no `Promise::new(predecessor).transfer(deposit)` anywhere in `request_refund_callback`: [5](#0-4) 

In NEAR's async execution model, two `request_refund` calls can be submitted in the same or adjacent blocks before either callback executes. Both light-client calls return `true`; callback A stores the request; callback B panics. The 2 NEAR from caller B is gone.

### Impact Explanation
The second caller permanently loses their 2 NEAR anti-spam deposit. No refund request is stored for them. The invariant stated in the doc comment — *"The deposit is NOT refunded — it covers request storage"* — is violated in the failure case: the deposit is consumed but no storage is allocated. [6](#0-5) 

This is a permanent, irrecoverable loss of user funds (2 NEAR per victim). No BTC/nBTC is at risk, so this is **Medium** severity.

### Likelihood Explanation
The race requires two concurrent calls for the same UTXO. This can happen:
- Accidentally: a user double-submits (e.g., network retry)
- Intentionally: a griever front-runs a known `request_refund` call (the UTXO details are visible on-chain)

The `test_refund_duplicate_request` test confirms the "Refund request already exists" panic path is reachable, but it tests sequential calls (first succeeds, second fails at the callback), not the concurrent case where both deposits are consumed. [7](#0-6) 

### Recommendation
In `request_refund_callback`, replace the `require!` duplicate check with a graceful branch that refunds the deposit to the original caller when the UTXO already has a pending request:

```rust
if self.data().refund_requests.contains_key(&utxo_storage_key) {
    // Refund the anti-spam deposit to the original caller
    Promise::new(env::signer_account_id())
        .transfer(self.required_balance_for_request_refund());
    return false;
}
```

The original caller's account ID must be threaded through as a callback parameter (similar to how `safe_mint_callback` refunds via `Promise::new(env::signer_account_id()).transfer(...)`). [8](#0-7) 

### Proof of Concept
1. Caller A and Caller B each call `request_refund` for the same `(tx_id, vout)` with 2 NEAR attached, before either callback executes.
2. Both light-client `verify_transaction_inclusion` calls return `true`.
3. Callback A executes: stores `RefundRequest` in `refund_requests`.
4. Callback B executes: `require!(!self.data().refund_requests.contains_key(...))` panics.
5. Assert: `refund_requests` contains exactly one entry; Caller B's 2 NEAR balance is reduced with no stored request and no refund. [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L489-491)
```rust
    /// Requires an attached deposit of at least `required_balance_for_request_refund()`.
    /// The deposit is NOT refunded — it covers request storage and acts as an anti-spam fee.
    ///
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L507-518)
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
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L602-604)
```rust
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn verify_refund_finalize(&mut self, tx_id: String, proof: TxInclusionProof) -> Promise {
```

**File:** contracts/satoshi-bridge/src/refund.rs (L146-184)
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

**File:** contracts/satoshi-bridge/tests/test_refund.rs (L303-363)
```rust
#[tokio::test]
#[cfg(not(feature = "zcash"))]
async fn test_refund_duplicate_request() {
    let worker = near_workspaces::sandbox().await.unwrap();
    let context = Context::new(&worker, Some(CHAIN.to_string())).await;

    let deposit_msg = DepositMsg {
        recipient_id: context.get_account_by_name("alice").sdk_id(),
        post_actions: None,
        extra_msg: None,
        safe_deposit: None,
        refund_address: Some(TARGET_ADDRESS.to_string()),
    };

    let deposit_address = context
        .get_user_deposit_address(deposit_msg.clone())
        .await
        .unwrap();

    let tx_bytes = generate_transaction_bytes(
        vec![(
            "d5d5069f02ad4ca31a16113903ab9fe9e8da6ddf20cad4b461b71e8b96050f22",
            0,
            None,
        )],
        vec![(deposit_address.as_str(), 100_000)],
    );

    // First request — should succeed
    check!(
        print "first request"
        context.request_refund(
            "alice",
            deposit_msg.clone(),
            TARGET_ADDRESS,
            tx_bytes.clone(),
            0,
            "0000000000000c3f818b0b6374c609dd8e548a0a9e61065e942cd466c426e00d"
                .to_string(),
            1,
            vec![],
            None
        )
    );

    // Second request for same UTXO — should fail
    check!(
        context.request_refund(
            "alice",
            deposit_msg,
            TARGET_ADDRESS,
            tx_bytes,
            0,
            "0000000000000c3f818b0b6374c609dd8e548a0a9e61065e942cd466c426e00d".to_string(),
            1,
            vec![],
            None
        ),
        "Refund request already exists for this UTXO"
    );
}
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L453-455)
```rust
            Promise::new(env::signer_account_id())
                .transfer(self.required_balance_for_safe_deposit())
                .detach();
```
