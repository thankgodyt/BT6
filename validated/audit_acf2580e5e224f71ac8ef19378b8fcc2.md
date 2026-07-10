### Title
Missing Caller Identity Check in `request_refund` Allows Attacker to Redirect BTC Refund to Arbitrary Address - (File: contracts/satoshi-bridge/src/refund.rs)

---

### Summary

`request_refund` in the satoshi-bridge contract does not verify that the caller (`env::predecessor_account_id()`) is the `deposit_msg.recipient_id`. Any unprivileged NEAR account can submit a refund request for another user's unprocessed BTC deposit and supply an attacker-controlled BTC address as the `refund_address` when `deposit_msg.refund_address` is `None`. If the DAO/Operator does not reject the request within `unsafe_refund_timelock_sec`, the bridge's MPC pipeline will send the victim's BTC to the attacker's address.

---

### Finding Description

`internal_request_refund` performs the following checks:

1. Attached NEAR deposit is sufficient (anti-spam fee).
2. If `deposit_msg.refund_address` is `Some(addr)`, the caller-supplied `refund_address` must match it.
3. The BTC transaction is valid (Light Client Merkle proof).
4. The output script at `vout` matches the deposit address derived from `deposit_msg`. [1](#0-0) 

There is **no check** that `env::predecessor_account_id() == deposit_msg.recipient_id`. The function is callable by any NEAR account for any deposit. [2](#0-1) 

When `deposit_msg.refund_address` is `None`, the caller freely supplies any BTC address as `refund_address`. That address is stored verbatim in the `RefundRequest` and later used as the payout destination in `execute_refund`. [3](#0-2) 

The `unsafe_refund_timelock_sec` config value is the only protection — it gives DAO/Operator a window to call `reject_refund`. If that window passes without rejection, `execute_refund` is open to anyone and the BTC is sent to the attacker's address. [4](#0-3) 

By contrast, the analogous `withdraw_rbf` path does enforce ownership: `internal_withdraw_rbf` explicitly requires `original_tx_btc_pending_info.account_id == account_id`. [5](#0-4) 

---

### Impact Explanation

**Critical.** An attacker who observes a victim's unprocessed BTC deposit (the `DepositMsg` is public — emitted by `get_user_deposit_address`) can:

1. Call `request_refund` with the victim's exact `deposit_msg` (where `refund_address: None`) and supply the attacker's own BTC address.
2. Pay the required NEAR storage deposit (anti-spam fee only, not a meaningful barrier).
3. Wait for `unsafe_refund_timelock_sec` to elapse without DAO/Operator intervention.
4. Call `execute_refund` — the bridge's MPC pipeline builds and signs a Bitcoin transaction paying the attacker's address.
5. Broadcast the signed transaction; the victim's BTC is permanently transferred to the attacker.

This constitutes **significant theft of user funds** with no on-chain recourse after the signed transaction is broadcast. [6](#0-5) 

---

### Likelihood Explanation

**Medium.** The attack requires:
- Knowledge of the victim's `deposit_msg` (public, emitted on-chain).
- The victim's deposit to be unprocessed (relayer down, or user changed mind).
- DAO/Operator to fail to reject the request within `unsafe_refund_timelock_sec`.

The first two conditions are realistic (relayer downtime, user-initiated refunds). The third is the primary mitigation, but it is operational rather than cryptographic — a slow or offline DAO/Operator makes the attack fully exploitable. [7](#0-6) 

---

### Recommendation

Add a caller identity check at the start of `internal_request_refund` (or in the public `request_refund` entry point) that enforces the caller is the `deposit_msg.recipient_id` when `deposit_msg.refund_address` is `None`:

```rust
// In internal_request_refund, before the Light Client call:
if deposit_msg.refund_address.is_none() {
    require!(
        env::predecessor_account_id() == deposit_msg.recipient_id,
        "Only the deposit recipient can request a refund with an unverified address"
    );
}
```

When `deposit_msg.refund_address` is `Some`, the pre-authorized address already constrains the payout destination, so the caller identity is less critical (though still worth restricting to the recipient for consistency). This mirrors the ownership check already present in `internal_withdraw_rbf`. [5](#0-4) 

---

### Proof of Concept

```
Setup:
  - Alice deposits 1 BTC to address derived from:
      DepositMsg { recipient_id: "alice.near", refund_address: None, ... }
  - Relayer goes offline; verify_deposit is never called.

Attack:
  1. Bob observes the DepositMsg from the on-chain LogDepositAddress event.
  2. Bob calls:
       request_refund(
         deposit_msg = { recipient_id: "alice.near", refund_address: None, ... },
         refund_address = "bc1q_BOB_ADDRESS",
         tx_bytes = <alice's BTC tx>,
         vout = 0,
         proof = <valid Merkle proof>,
         gas_fee = None
       )
     with the required NEAR storage deposit attached.
  3. request_refund_callback stores RefundRequest { refund_address: "bc1q_BOB_ADDRESS", ... }.
  4. unsafe_refund_timelock_sec elapses; DAO/Operator does not reject.
  5. Bob calls execute_refund(utxo_storage_key).
  6. Bridge builds PSBT paying "bc1q_BOB_ADDRESS", MPC signs it.
  7. Bob broadcasts the signed transaction.
  8. Alice's 1 BTC is permanently transferred to Bob.
``` [8](#0-7) [9](#0-8)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L137-159)
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L510-535)
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
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L582-589)
```rust
    pub fn execute_refund(
        &mut self,
        utxo_storage_key: String,
        chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
        self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
    }
```

**File:** contracts/satoshi-bridge/src/rbf/withdraw.rs (L43-46)
```rust
        require!(
            &original_tx_btc_pending_info.account_id == account_id,
            "Not allow"
        );
```
