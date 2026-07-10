### Title
Front-Running `request_refund_callback` Uniqueness Check Permanently Blocks User Refunds and Enables Fund Redirection — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

An unprivileged attacker can observe a victim's `request_refund` call in the NEAR mempool, copy all its parameters, substitute their own Bitcoin `refund_address`, and front-run the victim's transaction. Because the uniqueness guard in `request_refund_callback` fires after the asynchronous light-client cross-contract call, the attacker's callback settles first, inserting a refund request keyed to the same UTXO with the attacker's address. The victim's callback then panics with `"Refund request already exists for this UTXO"`, the victim loses their attached storage deposit, and their refund is blocked until the DAO manually rejects the attacker's entry.

---

### Finding Description

The refund flow is two-step: `internal_request_refund` dispatches a cross-contract call to the BTC light client, and only in the callback `request_refund_callback` is the refund request actually written to storage. The uniqueness guard lives entirely in the callback: [1](#0-0) 

```rust
// Double-check no duplicate (another request_refund could have landed between our check and callback)
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
```

The storage key is deterministically derived from the Bitcoin `tx_id` and `vout`: [2](#0-1) 

Both values are visible in the victim's NEAR transaction. The Merkle inclusion proof is public Bitcoin data. The `deposit_msg` is passed in plaintext. When `deposit_msg.refund_address` is `None`, the caller supplies any `refund_address` they choose: [3](#0-2) 

This means an attacker can copy every parameter from the victim's in-flight transaction, replace `refund_address` with their own Bitcoin address, and submit with higher gas. The attacker's callback completes first; the victim's callback then hits the `require!` and panics.

The `unsafe_refund_timelock_sec` path applies when `deposit_msg.refund_address` is `None`, giving the DAO a window to reject: [4](#0-3) 

However, the DAO rejection is not guaranteed, and the attack can be repeated after each rejection, making the refund mechanism persistently unreliable for the victim.

---

### Impact Explanation

**Immediate (Medium):** The victim's `request_refund_callback` panics; the victim loses their attached NEAR storage deposit and their refund is blocked until the DAO calls `internal_reject_refund`. The attacker can repeat the attack after each rejection, permanently denying the victim's refund in practice.

**Escalated (Critical):** If the DAO does not reject within `unsafe_refund_timelock_sec`, the attacker calls `execute_refund` (which is callable by any account after the timelock elapses, as `resolve_execute_refund_timelock` only adjusts the wait period for unprivileged callers): [5](#0-4) 

`finalize_refund_with_psbt` then builds a Bitcoin transaction paying `refund_amount` to the attacker's address: [6](#0-5) 

The victim's deposited BTC is redirected to the attacker.

---

### Likelihood Explanation

- NEAR transactions are observable in the mempool before finality; front-running is a known NEAR attack vector.
- All parameters needed to replicate the call (`deposit_msg`, `tx_bytes`, `vout`, Merkle proof) are transmitted in plaintext.
- The attacker pays only the storage deposit (a small NEAR amount), which is refunded if the DAO rejects.
- No special role or key is required.
- The attack is most effective against users whose `deposit_msg.refund_address` is `None` (the common case where the refund address is supplied at request time).

---

### Recommendation

1. **Bind `refund_address` to the depositor identity**: derive or verify `refund_address` from the `deposit_msg` account so it cannot be substituted by a third party.
2. **Allow the original depositor to overwrite a pending request**: if a refund request already exists for a UTXO but the new caller's `deposit_msg` matches the existing one, permit replacement.
3. **Commit-reveal for `refund_address`**: accept a hash commitment in the initial call and reveal the address only in the callback, preventing parameter copying from the mempool.
4. **Restrict `execute_refund` to the original requester or privileged roles** when `deposit_msg.refund_address` is `None`.

---

### Proof of Concept

1. Alice submits `request_refund(deposit_msg={refund_address: None, ...}, refund_address="alice_btc_addr", tx_bytes, vout=0, proof)` with storage deposit attached.
2. Bob observes Alice's transaction in the NEAR mempool before the light-client cross-contract call resolves.
3. Bob submits `request_refund(deposit_msg={refund_address: None, ...}, refund_address="bob_btc_addr", tx_bytes, vout=0, proof)` with higher gas priority — all parameters identical except `refund_address`.
4. Bob's `request_refund_callback` executes first; `utxo_storage_key = "txid:0"` is inserted into `refund_requests` with `refund_address = "bob_btc_addr"`.
5. Alice's `request_refund_callback` reaches line 544: `refund_requests.contains_key("txid:0")` is `true` → `require!` panics → Alice's callback reverts; Alice loses her storage deposit.
6. Alice's refund is blocked. If the DAO does not reject Bob's request within `unsafe_refund_timelock_sec`, Bob calls `execute_refund("txid:0")`, which builds and signs a Bitcoin transaction paying Alice's deposited BTC to `"bob_btc_addr"`. [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
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
