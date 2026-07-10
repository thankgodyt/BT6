### Title
Unprivileged Caller Can Redirect Any Unfinalized BTC Deposit to an Attacker-Controlled Address via `request_refund` - (File: contracts/satoshi-bridge/src/api/bridge.rs, contracts/satoshi-bridge/src/refund.rs)

---

### Summary

Any unprivileged NEAR account can call `request_refund` with a valid on-chain deposit proof and an attacker-controlled BTC `refund_address` when the original `deposit_msg.refund_address` is `None`. After the `unsafe_refund_timelock_sec` elapses without DAO/Operator rejection, the attacker calls `execute_refund` and the bridge's MPC pipeline sends the deposit UTXO to the attacker's address instead of the legitimate depositor's address.

---

### Finding Description

`request_refund` in `bridge.rs` carries no `#[trusted_relayer]` attribute on the function itself — only `#[payable]` and `#[pause(except(roles(Role::DAO)))]` — making it callable by any NEAR account. [1](#0-0) 

Inside `internal_request_refund`, the only guard on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [2](#0-1) 

When `deposit_msg.refund_address` is `None` — the common case for standard deposits — the caller-supplied `refund_address` is accepted without any ownership or identity check. There is no requirement that the caller be the original depositor (`deposit_msg.recipient_id`) or that the `refund_address` belong to them.

`execute_refund` is similarly unrestricted: [3](#0-2) 

The only runtime protections are:
1. A longer `unsafe_refund_timelock_sec` (explicitly noted in `resolve_execute_refund_timelock` as time for DAO/Operator to reject suspicious requests).
2. DAO/Operator can call `reject_refund`.
3. A successful `verify_deposit` marks the UTXO as verified and blocks the refund. [4](#0-3) 

None of these are enforced atomically or unconditionally — they all depend on external actors acting in time.

The analog to the original report is direct: just as any registered vault could be supplied as the `receiver` in `commitToLien` to bypass the authorization check, any NEAR account can supply itself as the `refund_address` beneficiary in `request_refund` using a valid deposit proof it does not own, bypassing the ownership check entirely.

---

### Impact Explanation

If the relayer is delayed or offline (so `verify_deposit` is never called) and the DAO/Operator does not reject the malicious request within `unsafe_refund_timelock_sec`, the bridge's MPC pipeline constructs and signs a Bitcoin transaction sending the deposit UTXO to the attacker's address. The legitimate depositor loses their BTC permanently. This constitutes unauthorized release of underlying BTC — a Critical bridge impact.

---

### Likelihood Explanation

- Relayer downtime or failure is a realistic operational scenario.
- The `deposit_msg` for any pending deposit is observable on-chain (it is submitted as a parameter to `verify_deposit` calls visible in the mempool or transaction history, and the deposit address is derived from it).
- The attacker only needs to pay a small NEAR storage deposit to submit the request.
- The `unsafe_refund_timelock_sec` window may be long enough for the DAO to respond in normal operation, but the DAO/Operator is not guaranteed to be online 24/7.
- No collateral, no special role, and no cryptographic secret is required from the attacker.

---

### Recommendation

1. **Require caller identity**: In `request_refund`, assert that `env::predecessor_account_id() == deposit_msg.recipient_id` when `deposit_msg.refund_address` is `None`, so only the intended recipient can submit a refund with a caller-supplied address.
2. **Or mandate pre-authorized addresses**: Require `deposit_msg.refund_address` to be non-`None` for all permissionless refund requests; caller-supplied addresses should only be accepted from trusted relayers.
3. **Or restrict the function**: Apply `#[trusted_relayer]` to `request_refund` so only whitelisted relayers can submit refund requests.

---

### Proof of Concept

1. Alice deposits BTC. Her `deposit_msg` has `refund_address: None` and `recipient_id: "alice.near"`. The deposit address is derived and published on-chain.
2. The relayer goes offline; `verify_deposit` is never called for Alice's UTXO.
3. Attacker Bob observes Alice's deposit transaction and her `deposit_msg` (visible from a pending or failed `verify_deposit` call in the NEAR mempool or transaction history).
4. Bob calls `request_refund(alice_deposit_msg, "bob_btc_address", alice_tx_bytes, vout, proof, None)` with a small NEAR storage deposit attached.
5. `internal_request_refund` checks: `deposit_msg.refund_address` is `None` → the `if let Some(...)` branch is skipped → `"bob_btc_address"` is accepted without validation. [5](#0-4) 

6. The Light Client verifies the transaction inclusion; `request_refund_callback` stores the `RefundRequest` with `refund_address = "bob_btc_address"`. [6](#0-5) 

7. `unsafe_refund_timelock_sec` elapses without DAO/Operator rejection.
8. Bob calls `execute_refund(utxo_storage_key, None)`. The bridge builds a PSBT spending Alice's deposit UTXO with the output paying `"bob_btc_address"`, signs it via MPC, and broadcasts it. [7](#0-6) 

9. Alice's BTC is permanently transferred to Bob. Alice receives nothing.

### Citations

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L580-589)
```rust
    #[payable]
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

**File:** contracts/satoshi-bridge/src/refund.rs (L154-184)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L315-401)
```rust
    pub(crate) fn finalize_refund_with_psbt(
        &mut self,
        caller: AccountId,
        mut refund_request: RefundRequest,
        psbt: PsbtWrapper,
        refund_amount: u128,
        utxo_storage_key: String,
    ) {
        let gas_fee = refund_request.gas_fee;
        let refund_address = refund_request.refund_address.clone();

        let deposit_msg = refund_request.deposit_msg();
        let path = get_deposit_path(&deposit_msg);
        let vutxo = VUTXO::Current(UTXO {
            path,
            tx_bytes: refund_request.tx_bytes.0.clone(),
            vout: refund_request.vout,
            balance: u64::try_from(refund_request.amount)
                .unwrap_or_else(|_| env::panic_str("Amount overflow")),
        });

        let psbt_hex = psbt.serialize();
        let btc_pending_id = psbt.get_pending_id();

        if !self.check_account_exists(&caller) {
            self.internal_set_account(&caller, crate::Account::new(&caller));
        }
        self.require_pending_sign_capacity(&caller);

        let btc_pending_info = BTCPendingInfo {
            account_id: caller.clone(),
            btc_pending_id: btc_pending_id.clone(),
            transfer_amount: 0,
            actual_received_amount: refund_amount,
            withdraw_fee: 0,
            gas_fee,
            burn_amount: 0,
            psbt_hex,
            vutxos: vec![vutxo],
            signatures: vec![None; 1],
            tx_bytes_with_sign: None,
            create_time_sec: nano_to_sec(env::block_timestamp()),
            last_sign_time_sec: 0,
            state: PendingInfoState::Refund(OriginalState {
                stage: PendingInfoStage::PendingSign,
                max_gas_fee: gas_fee,
                last_rbf_time_sec: None,
                cancel_rbf_reserved: None,
            }),
        };

        require!(
            self.data_mut()
                .btc_pending_infos
                .insert(btc_pending_id.clone(), btc_pending_info.into())
                .is_none(),
            "pending info already exist"
        );
        self.internal_unwrap_mut_account(&caller)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());

        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());

        Event::RefundExecuted {
            utxo_storage_key: utxo_storage_key.clone(),
            amount: refund_request.amount.into(),
            refund_address,
        }
        .emit();

        Event::GenerateBtcPendingInfo {
            account_id: &caller,
            btc_pending_id: &btc_pending_id,
        }
        .emit();

        // Keep the request (so `execute_refund` can be called again to re-create
        // the transaction) but mark it executed; it is removed only when the
        // refund is finalized in `verify_refund_finalize`.
        refund_request.executed = true;
        self.data_mut()
            .refund_requests
            .insert(utxo_storage_key, refund_request.into());
```

**File:** contracts/satoshi-bridge/src/refund.rs (L496-580)
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
```
