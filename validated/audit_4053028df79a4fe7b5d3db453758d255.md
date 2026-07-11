### Title
Missing Pre-Check for Duplicate Refund Requests Causes Permanent Loss of Caller's Storage Deposit - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary
`internal_request_refund` performs no duplicate-existence check before dispatching the async light-client verification call. The only guard lives inside the callback (`request_refund_callback`). Because NEAR does not refund an attached deposit when a callback panics, any caller whose callback is rejected due to a duplicate loses their entire storage deposit permanently.

### Finding Description
The vulnerability class from the reference report is **duplicate entries accepted without pre-validation**, allowing a race or griefing path. The bridge analog is in the refund subsystem.

`internal_request_refund` immediately fires the light-client cross-contract call without first checking whether a refund request for the same UTXO already exists or whether the UTXO was already finalized via `verify_deposit`: [1](#0-0) 

The only duplicate guard is inside `request_refund_callback`, executed asynchronously after the light-client round-trip: [2](#0-1) 

The comment on line 543 even reads *"Double-check no duplicate … could have landed between our check and callback"* — but there is **no first check**; the callback check is the sole guard. [3](#0-2) 

The storage deposit is required up-front and is explicitly documented as non-refundable: [4](#0-3) 

When `request_refund_callback` panics (via `require!`), NEAR rolls back state changes but does **not** return the already-transferred attached deposit. The deposit is permanently absorbed by the contract.

### Impact Explanation
An attacker who observes a pending `request_refund` transaction (BTC transaction data is public on-chain) can front-run it with an identical call for the same `(tx_id, vout)` UTXO. The attacker's callback succeeds first; the victim's callback panics on the duplicate check, and the victim's storage deposit (~2 NEAR, as sized by `required_balance_for_request_refund`) is permanently lost. The attacker's own deposit is consumed by the legitimate refund request they created, but they retain control of the refund flow (they specified the `refund_address`). This constitutes a publicly reachable, attacker-triggered permanent loss of caller funds in a production bridge path without direct BTC/nBTC theft.

**Impact: Low** — permanent loss of NEAR storage deposits; no direct BTC/nBTC theft.

### Likelihood Explanation
BTC deposit transactions are publicly visible. Any NEAR account that can call `request_refund` can observe a pending refund submission and front-run it. The attack requires no special privilege beyond being a valid caller of the function.

**Likelihood: Low** — requires mempool observation and front-running timing, but is fully permissionless once the attacker has the public BTC transaction data.

### Recommendation
Add an early-exit guard at the start of `internal_request_refund`, before the light-client call is dispatched:

```rust
pub(crate) fn internal_request_refund(...) -> Promise {
    // ... existing deposit/size checks ...

    let utxo_storage_key = generate_utxo_storage_key(
        transaction.compute_txid().to_string(),
        u32::try_from(vout).unwrap_or_else(|_| env::panic_str("vout overflow")),
    );
    require!(
        !self.data().verified_deposit_utxo.contains(&utxo_storage_key),
        "UTXO already verified via deposit"
    );
    require!(
        !self.data().refund_requests.contains_key(&utxo_storage_key),
        "Refund request already exists for this UTXO"
    );

    // ... proceed with light-client call ...
}
```

This mirrors the existing callback checks and prevents wasted gas and lost deposits before the expensive async call is made.

### Proof of Concept
1. Alice sends BTC to the bridge deposit address; the deposit is never finalized.
2. Alice constructs a `request_refund` call for `(tx_id, vout)` with 2 NEAR attached.
3. Bob (attacker) observes Alice's pending transaction, copies the public `deposit_msg` and `tx_bytes`, and submits an identical `request_refund` with a higher gas price, landing first.
4. Bob's `request_refund_callback` succeeds; the refund request is stored under Bob's chosen `refund_address`.
5. Alice's `request_refund_callback` hits the `require!` at line 544 and panics.
6. Alice's 2 NEAR storage deposit is permanently retained by the contract; she receives nothing back.
7. Bob can now call `execute_refund` after the timelock and redirect Alice's BTC to his own address (if `deposit_msg.refund_address` was `None`). [5](#0-4)

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
