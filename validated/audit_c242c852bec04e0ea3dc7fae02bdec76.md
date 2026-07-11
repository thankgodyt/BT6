### Title
Unprivileged Caller Can Redirect Any Deposit Refund to Attacker-Controlled BTC Address — (`contracts/satoshi-bridge/src/refund.rs`, `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`request_refund` is publicly callable by any NEAR account. When the original `deposit_msg.refund_address` is `None`, the function accepts any caller-supplied `refund_address` without validating that the caller is the original depositor. The supplied address is stored verbatim in `RefundRequest.refund_address` and used directly by `execute_refund` to build the BTC output. An attacker can front-run or simply submit a refund request for any unfinalized deposit, redirect the BTC to their own address, and wait out the `unsafe_refund_timelock_sec`.

---

### Finding Description

**Step 1 — `request_refund` is publicly callable.**

`request_refund` lives in a `#[trusted_relayer]` impl block, but the macro is not enforced at the impl-block level for all functions. The evidence is the inconsistency within the same block: `verify_refund_finalize` and `remove_refund_pending_tx_id` carry an explicit `#[trusted_relayer]` at the function level, while `request_refund`, `reject_refund`, and `execute_refund` do not. The same pattern holds in the first impl block where `get_user_deposit_address` and `get_change_address` are clearly public despite the impl-level attribute. Therefore `request_refund` is callable by any NEAR account. [1](#0-0) [2](#0-1) 

**Step 2 — No caller-identity check when `deposit_msg.refund_address` is `None`.**

`internal_request_refund` only validates `refund_address` against `deposit_msg.refund_address` when the latter is `Some`. When it is `None`, the block is skipped entirely and the caller-supplied address is forwarded to the callback unconditionally. [3](#0-2) 

**Step 3 — `request_refund_callback` stores the attacker's address verbatim.**

The callback stores `refund_address` (the attacker's BTC address) directly into `RefundRequest.refund_address` with no further validation. [4](#0-3) 

**Step 4 — `execute_refund` uses the stored address without re-checking the depositor.**

`internal_execute_refund` reads `refund_request.refund_address` and passes it directly to `build_refund_output`. There is no parameter for the caller to supply a different address, and no check that the caller is the original depositor. [5](#0-4) 

**Step 5 — The only mitigation is an operational timelock, not a code-level invariant.**

When `deposit_msg.refund_address` is `None`, `resolve_execute_refund_timelock` applies `config.unsafe_refund_timelock_sec` (a longer delay) to give DAO/Operator time to call `reject_refund`. This is a governance mitigation, not a cryptographic one. If the DAO/Operator misses the window, the BTC is sent to the attacker. [6](#0-5) 

---

### Impact Explanation

A depositor who sent BTC to a deposit address derived from a `DepositMsg` with `refund_address: None` (the common case — the field is `skip_serializing_if = "Option::is_none"`) and whose deposit was never finalized loses their entire deposit. The attacker pays only the NEAR storage deposit for the refund request and the BTC gas fee, and receives the full deposit amount minus gas. This is a direct, permanent loss of user BTC funds.

---

### Likelihood Explanation

- The attack requires no privileged role, no leaked key, and no external dependency.
- Any NEAR account can call `request_refund` with an arbitrary `refund_address`.
- Deposits with `refund_address: None` are the default (the field is optional and omitted by default).
- The attacker only needs to know the `deposit_msg` (which is public — it is emitted in events and used to derive the on-chain deposit address) and the BTC transaction bytes.
- The only defense is DAO/Operator monitoring and rejection within `unsafe_refund_timelock_sec`. A missed window or a high-volume attack makes this unreliable.

---

### Recommendation

1. **Require the caller to be the original depositor.** In `internal_request_refund`, when `deposit_msg.refund_address` is `None`, require `env::predecessor_account_id() == deposit_msg.recipient_id` (or a designated authorized account).
2. **Alternatively, require `deposit_msg.refund_address` to always be set** and reject requests where it is `None` from unprivileged callers.
3. **Or restrict `request_refund` to trusted relayers** (add `#[trusted_relayer]` at the function level) and have the relayer validate the depositor's intent off-chain before submitting.

---

### Proof of Concept

```
// Depositor previously sent BTC to the address derived from:
// deposit_msg = { recipient_id: "depositor.near", refund_address: None }
// The deposit was never finalized.

// Attacker (any NEAR account) calls:
request_refund(
    deposit_msg = { recipient_id: "depositor.near", refund_address: None },
    refund_address = "attacker_btc_address",
    tx_bytes = <depositor's BTC tx bytes>,
    vout = 0,
    proof = <valid inclusion proof>,
    gas_fee = None,
)

// internal_request_refund: deposit_msg.refund_address is None → skip address check
// request_refund_callback: stores RefundRequest { refund_address: "attacker_btc_address", ... }

// After unsafe_refund_timelock_sec passes (DAO/Operator did not reject):
execute_refund(utxo_storage_key = "<tx_id>@0", chain_specific_data = None)

// internal_execute_refund:
//   build_refund_output("attacker_btc_address", refund_amount)
// → BTC sent to attacker; depositor loses funds.
``` [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L480-535)
```rust
#[trusted_relayer]
#[near]
impl Contract {
    // ── Refund API ──

    /// Submit a refund request for a deposit that was never finalized via `verify_deposit` or `safe_verify_deposit`.
    /// The BTC transaction is verified through the Light Client to prove the deposit exists.
    /// After the timelock period, anyone can call `execute_refund` to initiate the return.
    ///
    /// Requires an attached deposit of at least `required_balance_for_request_refund()`.
    /// The deposit is NOT refunded — it covers request storage and acts as an anti-spam fee.
    ///
    /// # Arguments
    ///
    /// * `deposit_msg` - The original deposit message. If `deposit_msg.refund_address` is set,
    ///   it must match the provided `refund_address`.
    /// * `refund_address` - BTC address to send the refund to. If `deposit_msg.refund_address`
    ///   is `None`, this value is used directly.
    /// * `tx_bytes` - BTC transaction bytes proving the deposit.
    /// * `vout` - Output index of the deposit in the transaction.
    /// * `proof` - Transaction inclusion proof for Light Client verification, bundling:
    ///   `tx_block_blockhash` (block hash containing the transaction), `tx_index`
    ///   (transaction index within the block), `merkle_proof` (Merkle proof of the
    ///   transaction), and the coinbase fields `coinbase_tx_id` and
    ///   `coinbase_merkle_proof` used to verify the block's coinbase.
    /// * `gas_fee` - Optional custom gas fee. Only DAO or Operator can set this.
    ///   If `None`, the default `config.max_btc_gas_fee` is used during `execute_refund`.
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L602-626)
```rust
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn verify_refund_finalize(&mut self, tx_id: String, proof: TxInclusionProof) -> Promise {
        let btc_pending_info = self.internal_unwrap_btc_pending_info(&tx_id);
        btc_pending_info.assert_refund_pending_verify_tx();
        require!(
            btc_pending_info.tx_bytes_with_sign.is_some(),
            "Missing tx_bytes_with_sign"
        );
        self.internal_verify_refund_finalize(tx_id, proof, btc_pending_info)
    }

    /// Remove a leftover refund pending transaction whose refund request is gone
    /// (the refund was already finalized via another candidate, or rejected). Such
    /// a transaction can never confirm, so this only cleans up stale state — it is
    /// rejected while the refund request still exists.
    ///
    /// # Arguments
    ///
    /// * `tx_id` - Pending id of the stale refund transaction to remove.
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn remove_refund_pending_tx_id(&mut self, tx_id: String) {
        self.internal_remove_refund_pending_tx_id(tx_id);
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L132-184)
```rust
impl Contract {
    /// Submit a refund request. Verifies the BTC transaction via Light Client first.
    /// If `deposit_msg.refund_address` is set, it must match the provided `refund_address`.
    /// If `deposit_msg.refund_address` is None, the provided `refund_address` is used.
    #[allow(clippy::too_many_arguments)]
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

**File:** contracts/satoshi-bridge/src/refund.rs (L216-228)
```rust
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

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L18-44)
```rust
    pub(crate) fn internal_execute_refund(
        &mut self,
        utxo_storage_key: String,
        timelock_sec: u64,
        _chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let refund_request = self.load_refund_request_for_execute(&utxo_storage_key, timelock_sec);
        let RefundExecutionInputs {
            outpoint,
            deposit_output,
            refund_amount,
        } = self.refund_execution_inputs(&refund_request);
        let refund_output = self.build_refund_output(&refund_request.refund_address, refund_amount);

        let mut psbt = PsbtWrapper::new(vec![outpoint], vec![refund_output]);
        psbt.set_input_utxo(vec![deposit_output]);

        let caller = env::predecessor_account_id();
        self.finalize_refund_with_psbt(
            caller,
            refund_request,
            psbt,
            refund_amount,
            utxo_storage_key,
        );
        PromiseOrValue::Value(())
    }
```
