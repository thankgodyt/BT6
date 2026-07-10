### Title
User-Controlled `refund_address` Not Validated at Storage Time Causes `execute_refund` to Always Panic — (File: contracts/satoshi-bridge/src/refund.rs)

---

### Summary

The `request_refund` entry point accepts a caller-supplied `refund_address` string and stores it in a `RefundRequest` without any format validation. The address is only parsed — and panics if malformed — inside `build_refund_output`, which is called during `execute_refund`. An unprivileged attacker can front-run a legitimate refund request for any pending UTXO with an invalid address, permanently blocking that UTXO's refund path until a DAO/Operator manually rejects the poisoned request.

---

### Finding Description

**Phase 1 — `request_refund` / `request_refund_callback` (no address validation):**

`internal_request_refund` decodes the transaction, computes confirmations, and fires an async light-client verification. The `refund_address` string is forwarded verbatim to the callback with zero format checking. [1](#0-0) 

`request_refund_callback` verifies the light-client result, checks for duplicates, resolves the gas fee, and stores the `RefundRequest` — again without parsing or validating `refund_address`. [2](#0-1) 

The duplicate-UTXO guard that blocks a second request for the same UTXO is the key state-lock: [3](#0-2) 

**Phase 2 — `execute_refund` → `build_refund_output` (address parsed, panics):**

`build_refund_output` is the first point where the stored address is actually parsed. If it is malformed, the call panics unconditionally: [4](#0-3) 

`execute_refund` is publicly callable (no `#[trusted_relayer]` or `#[access_control_any]` at the function level): [5](#0-4) 

**Attack path:**

1. Attacker observes a BTC deposit UTXO that has not yet been finalized via `verify_deposit` (all data — `tx_bytes`, `deposit_msg`, Merkle proof — is public on-chain).
2. Attacker calls `request_refund` with a syntactically invalid `refund_address` (e.g., `"INVALID"`), paying the required storage deposit.
3. Light-client verification succeeds (the BTC transaction is real); `request_refund_callback` stores the poisoned `RefundRequest`.
4. Every subsequent call to `execute_refund` for that UTXO panics at `Address::parse(...).expect("Invalid refund address")`.
5. The duplicate guard prevents the victim from submitting a corrected refund request for the same UTXO.
6. The victim's BTC remains locked until a DAO/Operator calls `reject_refund`.

---

### Impact Explanation

The victim's BTC deposit is temporarily locked: they cannot obtain a refund until privileged operator intervention. The `reject_refund` path requires either DAO/Operator action or the UTXO being finalized via `verify_deposit`. [6](#0-5) 

This matches **Medium — attacker-triggered temporary locking of bridged funds**.

---

### Likelihood Explanation

All inputs needed to construct the attack (BTC transaction bytes, Merkle proof, `deposit_msg`) are publicly observable on the Bitcoin blockchain. The only cost to the attacker is the non-refundable storage deposit for the refund request. No privileged role is required. Any NEAR account can call `request_refund`. [7](#0-6) 

---

### Recommendation

Validate `refund_address` format eagerly — either in `internal_request_refund` (before the async light-client call) or at the start of `request_refund_callback` (before storing the request) — by calling `Address::parse` and rejecting the transaction if parsing fails. This mirrors the validation already performed in `build_refund_output` and ensures no unexecutable refund request can be committed to state. [8](#0-7) 

---

### Proof of Concept

```
# 1. Observe a pending BTC deposit UTXO (tx_id, vout, deposit_msg, tx_bytes, proof)
#    — all public on the Bitcoin blockchain.

# 2. Attacker calls request_refund with a malformed refund_address:
near call <bridge> request_refund '{
  "deposit_msg": { "recipient_id": "<victim.near>" },
  "refund_address": "INVALID_BTC_ADDRESS",
  "tx_bytes": "<base64_tx>",
  "vout": 0,
  "proof": { ... },
  "gas_fee": null
}' --deposit <storage_deposit> --accountId attacker.near

# 3. Light-client verification passes (real BTC tx). RefundRequest stored with
#    refund_address = "INVALID_BTC_ADDRESS".

# 4. Anyone calls execute_refund — panics every time:
near call <bridge> execute_refund '{
  "utxo_storage_key": "<tx_id>@0",
  "chain_specific_data": null
}' --accountId anyone.near
# → panics: "Invalid refund address"

# 5. Victim cannot submit a new request — duplicate guard fires:
# → "Refund request already exists for this UTXO"

# 6. Funds remain locked until DAO/Operator calls reject_refund.
```

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L581-589)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn execute_refund(
        &mut self,
        utxo_storage_key: String,
        chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
        self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
    }
```
