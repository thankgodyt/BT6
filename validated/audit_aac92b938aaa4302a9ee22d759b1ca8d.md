### Title
Unvalidated `refund_address` String in `request_refund` Causes Permanently Stuck Refund State Requiring Operator Intervention - (File: `contracts/satoshi-bridge/src/refund.rs`)

### Summary
The `request_refund` function accepts a `refund_address: String` parameter that is stored verbatim without any BTC/ZEC address format validation. When `deposit_msg.refund_address` is `None`, any arbitrary string is accepted and persisted. The address is only parsed later during `execute_refund` → `build_refund_output`, where an invalid address causes a panic. Because there is no user-accessible cancellation path, the refund request becomes permanently stuck until a privileged DAO/Operator calls `reject_refund`.

### Finding Description

In `request_refund` (the public entry point), the `refund_address` parameter flows directly into `internal_request_refund` with no format check: [1](#0-0) 

Inside `internal_request_refund`, the only guard on `refund_address` is a string-equality check against `deposit_msg.refund_address` when that field is `Some`. When it is `None`, the raw caller-supplied string is forwarded to the callback and stored: [2](#0-1) 

The callback stores the unvalidated string directly into `RefundRequest.refund_address`: [3](#0-2) 

Address parsing is deferred until `execute_refund` calls `build_refund_output`, which calls `Address::parse(...).expect("Invalid refund address")`: [4](#0-3) 

If the address is invalid, `build_refund_output` panics. Because `finalize_refund_with_psbt` is never reached, neither `verified_deposit_utxo` nor `refund_request.executed` is set. The `RefundRequest` remains in storage with no user-accessible removal path — only `internal_reject_refund` (callable by DAO/Operator) can clear it: [5](#0-4) 

### Impact Explanation

A user who submits `request_refund` with an invalid `refund_address` (when `deposit_msg.refund_address` is `None`) will:

1. Have their refund request stored and the timelock started.
2. Find that every subsequent `execute_refund` call panics.
3. Be unable to self-cancel — there is no user-facing cancellation function.
4. Require DAO/Operator intervention via `reject_refund` to unblock the UTXO.

Until the DAO acts, the deposit UTXO is in a limbo state: the refund cannot execute, and the user's BTC on Bitcoin remains unrefunded. This matches the **Medium** impact class: *stuck bridge state requiring operator intervention*.

### Likelihood Explanation

The `request_refund` path is reachable by any unprivileged NEAR account that has made a BTC deposit. The `deposit_msg.refund_address = None` case (where the caller freely supplies `refund_address`) is the common path for users who did not pre-commit a refund address at deposit time. A user error (typo, wrong network prefix, copy-paste of a non-address string) is realistic. No special privileges or external dependencies are required to trigger the stuck state.

### Recommendation

Validate `refund_address` against the configured chain at the point of entry in `internal_request_refund`, before the Light Client cross-contract call is dispatched:

```rust
// In internal_request_refund, after the refund_address equality check:
crate::network::Address::parse(&refund_address, self.internal_config().chain.clone())
    .unwrap_or_else(|e| env::panic_str(&format!("Invalid refund_address: {e}")));
```

This mirrors how `build_refund_output` already parses the address, but moves the check to the entry point so invalid addresses are rejected immediately rather than after the request is persisted.

### Proof of Concept

1. Alice deposits BTC to a deposit address derived from a `DepositMsg` with `refund_address: None`.
2. Alice calls `request_refund` with `refund_address = "not-a-valid-btc-address"` and a valid `deposit_msg` (with `refund_address: None`).
3. `internal_request_refund` passes the equality check (skipped because `deposit_msg.refund_address` is `None`) and dispatches the Light Client verification.
4. `request_refund_callback` stores the `RefundRequest` with `refund_address = "not-a-valid-btc-address"`.
5. After the `unsafe_refund_timelock_sec` elapses, anyone calls `execute_refund`.
6. `build_refund_output` calls `Address::parse("not-a-valid-btc-address", chain).expect(...)` → **panics**.
7. Alice has no way to remove the stuck request. The BTC deposit remains unrefunded until a DAO/Operator calls `reject_refund`. [6](#0-5) [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L510-534)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L187-196)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L293-308)
```rust
    /// Build a transparent refund output paying `refund_amount` to `refund_address`.
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
