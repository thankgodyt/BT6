### Title
Unauthenticated `request_refund` Allows Any Caller to Redirect a Victim's BTC Refund to an Attacker-Controlled Address — (`File: contracts/satoshi-bridge/src/api/bridge.rs`, `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`request_refund` does not verify that the caller is the `deposit_msg.recipient_id`. Any unprivileged NEAR account can submit a refund request for another user's unfinalized deposit and supply an attacker-controlled BTC address as the `refund_address`. After the `unsafe_refund_timelock_sec` elapses without DAO intervention, the attacker calls `execute_refund` and the bridge MPC-signs a transaction that sends the victim's BTC to the attacker's address.

---

### Finding Description

`request_refund` is a public, permissionless entry point. Its only caller-identity check is an optional privilege test used to allow DAO/Operator to set a custom `gas_fee`:

```rust
// contracts/satoshi-bridge/src/api/bridge.rs  (lines 519-526)
if gas_fee.is_some() {
    let caller = env::predecessor_account_id();
    require!(
        self.acl_has_role(Role::DAO.into(), caller.clone())
            || self.acl_has_role(Role::Operator.into(), caller),
        "Only DAO or Operator can specify custom gas_fee"
    );
}
``` [1](#0-0) 

There is no check that `env::predecessor_account_id()` equals `deposit_msg.recipient_id`. The function then delegates to `internal_request_refund`, which only validates that the BTC transaction is real and that the output script matches the deposit address derived from `deposit_msg`:

```rust
// contracts/satoshi-bridge/src/refund.rs  (lines 154-158)
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [2](#0-1) 

When `deposit_msg.refund_address` is `None` (the common case for standard deposits), the caller-supplied `refund_address` is accepted without restriction and stored verbatim in the `RefundRequest`:

```rust
// contracts/satoshi-bridge/src/refund.rs  (lines 564-574)
let refund_request = RefundRequest {
    deposit_msg_json: serde_json::to_string(&deposit_msg).unwrap(),
    ...
    refund_address,   // ← attacker-controlled
    ...
};
``` [3](#0-2) 

The `resolve_execute_refund_timelock` function applies a longer `unsafe_refund_timelock_sec` for this case, with a comment acknowledging the risk:

```rust
// contracts/satoshi-bridge/src/refund.rs  (lines 223-227)
} else {
    // Refund address supplied by caller of `request_refund`: longer
    // timelock to give DAO/Operator time to reject suspicious requests.
    config.unsafe_refund_timelock_sec
}
``` [4](#0-3) 

After the timelock, `execute_refund` is also permissionless — any account can call it. The bridge then builds a PSBT paying `refund_amount` to the stored `refund_address` and submits it to the MPC for signing, permanently redirecting the victim's BTC. [5](#0-4) 

---

### Impact Explanation

If the DAO does not actively monitor and reject the request within `unsafe_refund_timelock_sec`, the bridge MPC signs and broadcasts a BTC transaction paying the victim's deposit to the attacker's address. The victim's BTC is permanently lost. This matches the allowed impact: **significant loss or theft of user funds**.

---

### Likelihood Explanation

The attack is reachable by any unprivileged NEAR account. It requires only:
1. A deposit that was never finalized via `verify_deposit` (relayer failure, network issue, etc.).
2. The victim's `deposit_msg` (publicly derivable from the deposit address or on-chain events).
3. The victim's BTC transaction bytes and a valid Merkle proof (all public on-chain data).
4. DAO inaction during `unsafe_refund_timelock_sec`.

The attacker pays only the NEAR storage deposit for `request_refund` and `execute_refund`, which is negligible compared to the stolen BTC. The DAO inaction window is a realistic failure mode (DAO offline, slow monitoring, high volume of requests).

---

### Recommendation

Add a caller-identity check in `internal_request_refund` (or at the `request_refund` entry point) that requires `env::predecessor_account_id() == deposit_msg.recipient_id` when `deposit_msg.refund_address` is `None`. Alternatively, require the caller to prove ownership of the deposit by signing a message with the recipient's key, or restrict `request_refund` to the `recipient_id` unconditionally.

---

### Proof of Concept

1. Alice sends 1 BTC to her deposit address derived from `DepositMsg { recipient_id: "alice.near", refund_address: None, ... }`.
2. The relayer fails; `verify_deposit` is never called. The UTXO is unfinalized.
3. Bob (attacker) observes Alice's BTC transaction on-chain and reconstructs her `deposit_msg` from the deposit address derivation (`get_deposit_path` hashes the full JSON).
4. Bob calls:
   ```
   request_refund(
     deposit_msg = alice_deposit_msg,
     refund_address = "bc1q_bob_address",
     tx_bytes = alice_tx_bytes,
     vout = 0,
     proof = valid_merkle_proof,
     gas_fee = None
   )
   ```
   attaching the required NEAR storage deposit.
5. `request_refund_callback` verifies the Merkle proof and stores `RefundRequest { refund_address: "bc1q_bob_address", ... }`.
6. DAO does not reject within `unsafe_refund_timelock_sec`.
7. Bob calls `execute_refund(utxo_storage_key)`. The bridge builds a PSBT paying Alice's BTC to Bob's address and submits it to MPC for signing.
8. The signed transaction is broadcast; Alice's 1 BTC is sent to Bob. [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

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

**File:** contracts/satoshi-bridge/src/refund.rs (L223-227)
```rust
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
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

**File:** contracts/satoshi-bridge/src/refund.rs (L564-574)
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
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L49-52)
```rust
pub fn get_deposit_path(deposit_msg: &DepositMsg) -> String {
    let deposit_msg_string = serde_json::to_string(&deposit_msg).unwrap();
    hex::encode(env::sha256(deposit_msg_string.as_bytes()))
}
```
