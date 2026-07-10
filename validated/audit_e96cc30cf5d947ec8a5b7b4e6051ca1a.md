### Title
Concurrent `request_refund` Calls for the Same UTXO Cause Permanent Loss of Second Caller's Storage Deposit — (`contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`request_refund` is a public, unprivileged, payable function. Two concurrent calls for the same UTXO both pass the async light-client XCC, but only the first callback can insert the refund request. The second callback panics via `require!` after the deposit is already irrevocably transferred to the contract, with no refund path.

---

### Finding Description

The entry point is `request_refund` in `contracts/satoshi-bridge/src/api/bridge.rs`. Despite the `#[trusted_relayer]` attribute on the enclosing `impl` block, `request_refund` itself carries only `#[payable]` and `#[pause(...)]` — no per-method `#[trusted_relayer]`. Every other method in that block that actually requires relayer gating carries its own explicit `#[trusted_relayer]` (e.g., `verify_refund_finalize` at line 602, `remove_refund_pending_tx_id` at line 622). `request_refund`, `reject_refund`, and `execute_refund` do not, confirming they are publicly callable. [1](#0-0) 

The function delegates to `internal_request_refund`, which:
1. Verifies the attached deposit is sufficient (non-refundable by design).
2. Fires an async XCC to the light client.
3. Chains `request_refund_callback`. [2](#0-1) 

The callback, `request_refund_callback`, is `#[private]` and runs after the XCC resolves. It contains this guard:

```rust
// Double-check no duplicate (another request_refund could have landed between our check and callback)
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [3](#0-2) 

The developer comment explicitly acknowledges the race window. When the `require!` fires, the callback panics and its state changes revert — but the attached deposit from the original `request_refund` call was already transferred to the contract in the preceding transaction and is **not** rolled back. There is no `Promise::new(...).transfer(...)` or any other refund path in the callback for the failure branch. [4](#0-3) 

The contract documentation for `request_refund` explicitly states the deposit is non-refundable:

> "The deposit is NOT refunded — it covers request storage and acts as an anti-spam fee." [5](#0-4) 

This is intentional for the success path, but the same non-refundable behavior applies to the race-condition failure path, which is unintentional.

---

### Impact Explanation

Any caller whose `request_refund_callback` panics due to a duplicate key loses their entire attached storage deposit permanently. The deposit is held by the contract with no recovery mechanism. This is a broken callback rollback: the XCC succeeded, the original call completed, but the callback's failure does not undo the deposit transfer.

---

### Likelihood Explanation

NEAR's async execution model makes this straightforward to trigger:

- Two calls in the same or adjacent blocks both fire XCC to the light client for the same valid UTXO.
- Both XCCs succeed (the UTXO is real and confirmed).
- Callbacks execute sequentially; the second one always panics.

An attacker can deliberately front-run any legitimate `request_refund` submission by submitting their own call for the same UTXO immediately after observing it in the mempool or on-chain. The victim loses their deposit; the attacker's own deposit is safely stored as the winning refund request (which they can later abandon or let expire).

---

### Recommendation

In `request_refund_callback`, replace the hard `require!` on duplicate key with a graceful refund branch:

```rust
if self.data().refund_requests.contains_key(&utxo_storage_key) {
    // Refund the attached deposit back to the original caller
    Promise::new(env::signer_account_id())
        .transfer(env::attached_deposit());
    return false;
}
```

Alternatively, check for a duplicate key **before** firing the XCC in `internal_request_refund` (synchronous, no race window), and reject early with a full deposit refund.

---

### Proof of Concept

```
1. Alice calls request_refund(utxo=X, ...) attaching 2 NEAR.
   → internal_request_refund fires XCC to light client.

2. Bob calls request_refund(utxo=X, ...) attaching 2 NEAR.
   → internal_request_refund fires XCC to light client.

3. Alice's XCC resolves → request_refund_callback runs:
   - refund_requests.contains_key(X) == false → passes
   - Inserts RefundRequest for X
   - Returns true

4. Bob's XCC resolves → request_refund_callback runs:
   - refund_requests.contains_key(X) == true → require! panics
   - Callback reverts; no refund request stored for Bob
   - Bob's 2 NEAR deposit remains in the contract with no recovery path

Assert: Bob's 2 NEAR is permanently lost.
```

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L488-491)
```rust
    ///
    /// Requires an attached deposit of at least `required_balance_for_request_refund()`.
    /// The deposit is NOT refunded — it covers request storage and acts as an anti-spam fee.
    ///
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
