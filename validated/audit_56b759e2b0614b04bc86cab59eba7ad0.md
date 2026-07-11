### Title
Missing `refund_address` Format Validation in `request_refund_callback` Allows Stuck Refund State - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary
`request_refund_callback` stores the caller-supplied `refund_address` string into a `RefundRequest` without ever validating it as a well-formed BTC/ZEC address. Validation is deferred to `execute_refund` → `build_refund_output`, which panics on an invalid address. Because the refund request is already committed to storage at that point, the UTXO is permanently stuck in a pending-refund state until a privileged operator manually rejects it.

### Finding Description
In `request_refund_callback`, the `refund_address` parameter is accepted from the caller and written directly into `RefundRequest` with no call to `Address::parse()` or any other format check:

```rust
// contracts/satoshi-bridge/src/refund.rs  lines 564-578
let refund_request = RefundRequest {
    ...
    refund_address,          // ← stored verbatim, never validated
    ...
};
self.data_mut()
    .refund_requests
    .insert(utxo_storage_key, refund_request.into());
``` [1](#0-0) 

The only check performed on `refund_address` before storage is an equality comparison against `deposit_msg.refund_address` when that field is `Some`:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [2](#0-1) 

When `deposit_msg.refund_address` is `None`, no equality check is performed either, so any string — including a completely malformed address — passes through.

The actual address parsing is deferred to `build_refund_output`, called only during `execute_refund`:

```rust
// contracts/satoshi-bridge/src/refund.rs  lines 296-297
let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
    .expect("Invalid refund address");
``` [3](#0-2) 

If the stored address is invalid, `execute_refund` panics every time it is called for that request, making the refund permanently unexecutable without operator intervention.

### Impact Explanation
A refund request keyed by `utxo_storage_key` blocks any subsequent `request_refund` for the same UTXO (enforced at lines 544–547):

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [4](#0-3) 

Once a bad-address request is committed, the legitimate user cannot submit a corrected one. The deposit UTXO is effectively frozen: `verify_deposit` is also blocked because the refund request occupies the slot. The funds remain locked until a DAO/`RefundOperator` account calls `internal_reject_refund` to clear the request — a stuck bridge state requiring operator intervention.

### Likelihood Explanation
The attack is reachable by any unprivileged NEAR account. When a deposit is made with `deposit_msg.refund_address = None` (a common case where the user does not pre-authorize a refund address), `request_refund` is open to any caller who attaches the required storage deposit. An attacker can front-run the legitimate user's refund request with an invalid `refund_address` string (e.g., `"INVALID"`), paying only the storage deposit cost. The storage deposit requirement is a minor economic barrier, not a security control.

### Recommendation
Validate `refund_address` against the configured chain's address format inside `request_refund_callback` (or in `internal_request_refund` before the Light Client promise is dispatched) using the existing `Address::parse` utility:

```rust
// Validate before storing
Address::parse(&refund_address, config.chain.clone())
    .unwrap_or_else(|e| env::panic_str(&format!("Invalid refund_address: {e}")));
```

This mirrors the validation already applied to `target_btc_address` in the withdrawal path via `Config::target_script_pubkey`. [5](#0-4) 

### Proof of Concept

1. Alice deposits BTC with `deposit_msg.refund_address = None`.
2. Attacker observes the deposit transaction on-chain and calls `request_refund` with `refund_address = "NOT_A_VALID_ADDRESS"` and the correct `deposit_msg`, attaching the required storage deposit.
3. `request_refund_callback` stores the malformed address in `RefundRequest` without error.
4. Alice (or anyone) calls `execute_refund` for Alice's UTXO. `build_refund_output` calls `Address::parse("NOT_A_VALID_ADDRESS", chain)`, which returns `Err(...)`, and `.expect("Invalid refund address")` panics. The call reverts.
5. Alice cannot submit a new `request_refund` — the slot is occupied (line 544–547).
6. Alice's deposit is frozen until a DAO/`RefundOperator` calls `internal_reject_refund` to clear the stuck request. [6](#0-5) [7](#0-6)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L296-297)
```rust
        let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
            .expect("Invalid refund address");
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

**File:** contracts/satoshi-bridge/src/config.rs (L183-190)
```rust
    pub fn target_script_pubkey(&self, address_string: &str) -> Option<ScriptBuf> {
        let chain = self.get_utxo_network();

        Address::parse(address_string, chain)
            .unwrap_or_else(|e| env::panic_str(&format!("{address_string}: {e}")))
            .script_pubkey()
            .ok()
    }
```
