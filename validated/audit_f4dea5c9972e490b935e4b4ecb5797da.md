### Title
Missing BTC-address validation on `refund_address` in `request_refund` creates permanently unexecutable refund entries requiring operator intervention — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`internal_request_refund` stores a caller-supplied `refund_address` string without validating it as a syntactically correct BTC address for the configured chain. When `execute_refund` is later called for such a request, the contract panics inside `string_to_script_pubkey`, leaving the `RefundRequest` permanently stuck in `refund_requests` until a DAO/Operator manually calls `reject_refund`.

---

### Finding Description

**Root cause — no address-format check at request time.**

`internal_request_refund` performs three checks on `refund_address`: [1](#0-0) 

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
```

This guard only fires when `deposit_msg.refund_address` is `Some`. When it is `None` — the common case for callers who did not embed a refund address in their `DepositMsg` — **any arbitrary string is accepted and stored** as the refund destination. [2](#0-1) 

**Execution-time panic.**

During `execute_refund`, the bridge builds a PSBT and calls `string_to_script_pubkey` with the stored address: [3](#0-2) 

```rust
pub fn string_to_script_pubkey(&self, address_string: &str) -> ScriptBuf {
    let chain = self.get_utxo_network();
    Address::parse(address_string, chain)
        .unwrap_or_else(|e| env::panic_str(&format!("{address_string}: {e}")))
        .script_pubkey()
        .expect("Failed to get script pubkey")
}
```

An invalid address causes `env::panic_str`, reverting the transaction. The `RefundRequest` entry remains in `refund_requests` and **every subsequent call to `execute_refund` for that key will also panic**, because the stored address never changes.

**No self-service removal path.**

`reject_refund` — the only removal path — is restricted to DAO/Operator: [4](#0-3) 

Until an operator intervenes, the entry occupies contract storage and the associated UTXO cannot be finalized through the normal refund flow.

**Contrast with the validated withdrawal path.**

The withdrawal flow validates the PSBT (including all addresses) at creation time inside `check_withdraw_psbt_valid`, so no analogous stuck state can arise there: [5](#0-4) 

The refund path has no equivalent upfront address check.

---

### Impact Explanation

A stuck `RefundRequest` entry:
- Causes every public call to `execute_refund` for that key to panic.
- Occupies contract storage until an operator acts.
- Requires DAO/Operator intervention (`reject_refund`) to unblock — matching the allowed Medium/Low impact category: *"stuck bridge state requiring operator intervention"* and *"publicly reachable panic-driven fault in production bridge/token paths without direct theft."*

No funds are permanently lost: after rejection the user may re-submit with a valid address.

---

### Likelihood Explanation

- `request_refund` is a public, permissionless entry point callable by any NEAR account.
- The caller must supply a real, light-client-verified BTC transaction (non-trivial cost), but the `refund_address` string itself is entirely free-form.
- A single mistaken or malicious call is sufficient to create a stuck entry.
- The `unsafe_refund_timelock_sec` path (when `deposit_msg.refund_address` is `None`) is the most common real-world refund scenario, making this reachable in normal usage.

---

### Recommendation

Validate `refund_address` as a parseable BTC address for the configured chain inside `internal_request_refund`, before the cross-contract light-client call, mirroring the pattern already used in `string_to_script_pubkey`:

```rust
// Early in internal_request_refund, after the refund_address consistency check:
Address::parse(&refund_address, self.internal_config().get_utxo_network())
    .unwrap_or_else(|e| env::panic_str(&format!("Invalid refund_address: {e}")));
```

This ensures that any address stored in `refund_requests` is guaranteed to be parseable at execution time, eliminating the stuck-state class entirely.

---

### Proof of Concept

1. Alice calls `get_user_deposit_address` with `deposit_msg.refund_address = None`.
2. Alice sends BTC to the returned deposit address (real on-chain transaction).
3. Alice calls `request_refund` with `refund_address = "not_a_valid_btc_address"` and `deposit_msg.refund_address = None`.
4. The light client verifies the transaction; `request_refund_callback` stores the `RefundRequest` with the invalid address.
5. After `unsafe_refund_timelock_sec` elapses, anyone calls `execute_refund(utxo_storage_key)`.
6. `execute_refund` calls `string_to_script_pubkey("not_a_valid_btc_address")` → `env::panic_str` → transaction reverts.
7. The `RefundRequest` remains in `refund_requests`; step 6 repeats indefinitely.
8. A DAO/Operator must call `reject_refund(utxo_storage_key)` to unblock the contract state.

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

**File:** contracts/satoshi-bridge/src/config.rs (L168-175)
```rust
    pub fn string_to_script_pubkey(&self, address_string: &str) -> ScriptBuf {
        let chain = self.get_utxo_network();

        Address::parse(address_string, chain)
            .unwrap_or_else(|e| env::panic_str(&format!("{address_string}: {e}")))
            .script_pubkey()
            .expect("Failed to get script pubkey")
    }
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L89-98)
```rust
        let withdraw_fee = self.internal_config().withdraw_bridge_fee.get_fee(amount);
        let (actual_received_amount, gas_fee) = self.check_withdraw_psbt_valid(
            target_btc_address.clone(),
            &withdraw_change_address_script_pubkey,
            &psbt,
            &vutxos,
            amount,
            withdraw_fee,
            max_gas_fee,
        );
```
