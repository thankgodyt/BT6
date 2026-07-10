### Title
Any Caller Can Submit a Refund Request for Any Deposit UTXO With an Arbitrary BTC Refund Address — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`internal_request_refund` never verifies that the caller (`env::predecessor_account_id()`) is the NEAR account associated with the deposit. Any unprivileged NEAR account can submit a refund request for any deposit UTXO and supply an arbitrary BTC `refund_address`, bypassing the intended restriction that only the original depositor should control where their funds are returned.

---

### Finding Description

The `internal_request_refund` function performs several checks — storage deposit, tx-byte size, light-client proof, and (conditionally) that the provided `refund_address` matches `deposit_msg.refund_address` — but it never checks that the caller is the owner of the deposit. [1](#0-0) 

When `deposit_msg.refund_address` is `None` (the common case where the depositor did not pre-authorize a specific BTC return address), the caller is free to supply **any** BTC address: [2](#0-1) 

In `request_refund_callback`, the contract verifies the transaction proof and that the output script matches the deposit address derived from `deposit_msg`, but again never checks that `env::predecessor_account_id()` matches the NEAR account embedded in `deposit_msg`: [3](#0-2) 

The `deposit_msg` is derived from publicly visible Bitcoin transaction data (e.g., OP_RETURN output), so any observer can reconstruct it. An attacker can therefore:

1. Monitor the Bitcoin chain for deposits where `deposit_msg.refund_address` is `None`.
2. Extract the `deposit_msg` from the on-chain data.
3. Call `request_refund` with the victim's `deposit_msg` but their own BTC address as `refund_address`.
4. Wait for `unsafe_refund_timelock_sec` to elapse.
5. Call `execute_refund` — the refund PSBT is built paying the attacker's BTC address.

The only on-chain defense is the DAO/Operator rejecting the request during the timelock window: [4](#0-3) 

This is a trust-based, off-chain mitigation — not a cryptographic or contract-level access control check — directly analogous to the external report's pattern of relying on front-end restrictions instead of contract-level verification.

---

### Impact Explanation

If the DAO/Operator fails to monitor and reject the malicious request within `unsafe_refund_timelock_sec` (e.g., due to key unavailability, governance delay, or simply missing the event), the attacker's refund transaction is built and submitted to MPC for signing. The deposited BTC is redirected to the attacker's address. This constitutes a potential theft of user funds held by the bridge.

**Impact: Medium** — Bypass of bridge access policy; attacker-triggered redirection of bridged funds contingent on DAO inaction during the timelock.

---

### Likelihood Explanation

- The `deposit_msg` is publicly reconstructable from Bitcoin on-chain data.
- No special privilege is required; any NEAR account can call `request_refund`.
- The attacker only needs to wait for `unsafe_refund_timelock_sec`.
- The DAO must actively monitor every refund request and reject malicious ones — a liveness assumption that can fail.

Likelihood is **medium**: the attack is straightforward to execute but requires the DAO to be inattentive or unavailable during the timelock window.

---

### Recommendation

Add a caller-identity check inside `internal_request_refund` (or its public API wrapper) that asserts `env::predecessor_account_id()` matches the NEAR account ID embedded in `deposit_msg`. For example:

```rust
require!(
    env::predecessor_account_id() == deposit_msg.near_account_id,
    "Only the depositor may request a refund for this UTXO"
);
```

This enforces the access control at the contract level, eliminating reliance on the DAO's liveness to prevent fund redirection.

---

### Proof of Concept

1. Alice sends 1 BTC to the bridge. Her `deposit_msg` has `refund_address: None` and `near_account_id: alice.near`. The `deposit_msg` is readable from the Bitcoin transaction's OP_RETURN output.
2. Bob (attacker) reconstructs Alice's `deposit_msg` and calls `request_refund(deposit_msg=alice_msg, refund_address="bob_btc_addr", tx_bytes=..., vout=0, proof=...)` with sufficient attached NEAR for storage.
3. `request_refund_callback` succeeds: the proof is valid, the output script matches Alice's deposit address, and the UTXO is not yet verified. The refund request is stored with `refund_address = "bob_btc_addr"`.
4. After `unsafe_refund_timelock_sec` elapses (and assuming the DAO does not call `internal_reject_refund`), Bob calls `execute_refund`.
5. `finalize_refund_with_psbt` builds a PSBT paying `bob_btc_addr` and submits it to MPC for signing. [5](#0-4) 

Alice's deposited BTC is sent to Bob's address.

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

**File:** contracts/satoshi-bridge/src/refund.rs (L223-228)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L516-525)
```rust
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
```
