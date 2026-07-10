### Title
Front-Running `request_refund` Allows Attacker to Redirect Refund BTC to Attacker-Controlled Address — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`request_refund` is a permissionless function that accepts a caller-supplied `refund_address` when `deposit_msg.refund_address` is `None`. An attacker can observe a pending `request_refund` transaction, front-run it with an identical proof but a substituted `refund_address` pointing to the attacker's BTC wallet, and permanently redirect the victim's deposited BTC to themselves.

---

### Finding Description

`request_refund` is callable by any NEAR account. When the user's `deposit_msg.refund_address` field is `None`, the function accepts an arbitrary `refund_address` string from the caller with no binding to the caller's identity: [1](#0-0) 

The only guard is that if `deposit_msg.refund_address` is already set, the supplied `refund_address` must match it. When it is `None` (the common case for users who did not pre-commit a refund address), the caller's supplied value is stored verbatim: [2](#0-1) 

The refund request is keyed by `utxo_storage_key` (`txid@vout`). A duplicate-request guard prevents a second `request_refund` for the same UTXO from succeeding: [3](#0-2) 

Because the request is keyed only on the UTXO — not on the caller — whichever `request_refund` call lands first wins. The stored `refund_address` is later used unconditionally by `execute_refund` (which is itself permissionless) to construct the BTC refund transaction and send funds on-chain. [4](#0-3) 

---

### Impact Explanation

An attacker who successfully front-runs `request_refund` causes the victim's deposited BTC (which was never finalized via `verify_deposit`) to be sent to the attacker's BTC address instead of the victim's. The victim's own `request_refund` call fails with "Refund request already exists for this UTXO," leaving them with no recourse to recover their funds through the refund path. This is a direct, complete theft of user BTC funds.

**Impact: Critical** — unauthorized redirection and theft of user BTC held by the bridge.

---

### Likelihood Explanation

- `request_refund` is fully permissionless; no role or whitelist is required.
- All parameters needed to construct the front-running transaction (the `deposit_msg`, `tx_bytes`, `vout`, and `proof`) are visible in the victim's pending NEAR transaction before it is included in a block.
- The attacker only needs to attach a small NEAR storage deposit (`required_balance_for_request_refund`) to execute the attack.
- The `unsafe_refund_timelock_sec` delay before `execute_refund` is callable does not prevent the attack — it only delays the final BTC transfer.
- Any user whose `deposit_msg.refund_address` is `None` (the default, since `refund_address` is `skip_serializing_if = "Option::is_none"`) is vulnerable. [5](#0-4) 

**Likelihood: High** — the attack is cheap, requires no special privilege, and the victim population is all users who did not pre-commit a refund address in their `DepositMsg`.

---

### Recommendation

Bind the `refund_address` to the caller at submission time, or require that `deposit_msg.refund_address` always be set (non-`None`) before a `request_refund` can be accepted. Concretely:

- **Option A (preferred):** Require `deposit_msg.refund_address` to be `Some` and equal to the supplied `refund_address` for all callers, eliminating the caller-supplied free-form path entirely.
- **Option B:** Store `env::predecessor_account_id()` as the `requester` in `RefundRequest` and restrict `execute_refund` so that only the original requester (or DAO/Operator) can execute it, preventing the attacker from benefiting even if they front-run the request.

---

### Proof of Concept

1. User constructs `deposit_msg = { recipient_id: "user.near", refund_address: None, ... }` and calls `request_refund(deposit_msg, refund_address="1UserBtcAddr...", tx_bytes, vout, proof)` with the required NEAR storage deposit.
2. Attacker observes the pending transaction before block inclusion.
3. Attacker calls `request_refund(deposit_msg, refund_address="1AttackerBtcAddr...", tx_bytes, vout, proof)` with a higher priority (or simply races the same block), using the identical `deposit_msg`, `tx_bytes`, `vout`, and `proof` but substituting their own BTC address.
4. Attacker's `request_refund_callback` executes first. The check at line 154–158 passes (since `deposit_msg.refund_address` is `None`). The `RefundRequest` is stored with `refund_address = "1AttackerBtcAddr..."`.
5. User's `request_refund_callback` hits the duplicate guard at line 544–547 and reverts: "Refund request already exists for this UTXO."
6. After `unsafe_refund_timelock_sec` elapses, the attacker calls `execute_refund(utxo_storage_key, None)`. The bridge builds a BTC transaction paying `"1AttackerBtcAddr..."` and submits it via MPC signing.
7. The victim's BTC is permanently transferred to the attacker. [6](#0-5) [7](#0-6)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L201-228)
```rust
    pub(crate) fn resolve_execute_refund_timelock(&self, utxo_storage_key: &str) -> u64 {
        require!(
            env::attached_deposit() >= self.required_balance_for_execute_refund(),
            "Insufficient deposit for storage"
        );
        let caller = env::predecessor_account_id();
        let is_privileged =
            self.acl_has_any_role(vec![Role::DAO.into(), Role::RefundOperator.into()], caller);
        let refund_request: RefundRequest = self
            .data()
            .refund_requests
            .get(utxo_storage_key)
            .expect("Refund request not found")
            .into();
        let config = self.internal_config();
        if refund_request.deposit_msg().refund_address.is_some() {
            // Pre-authorized refund address: privileged users can fast-track.
            if is_privileged {
                0
            } else {
                config.refund_timelock_sec
            }
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
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

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L26-28)
```rust
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_address: Option<String>,
}
```
