### Title
Attacker Can Redirect Deposit Refund to Arbitrary BTC Address via Permissionless `request_refund` - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary
When `deposit_msg.refund_address` is `None`, any unprivileged NEAR account can call `request_refund` for any deposit UTXO and supply an arbitrary BTC `refund_address`. Because only one `RefundRequest` can exist per UTXO, an attacker who submits first locks out the legitimate depositor. If the DAO/Operator does not reject the request within `unsafe_refund_timelock_sec`, `execute_refund` sends the depositor's BTC to the attacker's address — a direct analog to the Dinari pattern of refund going to the wrong party.

### Finding Description
`internal_request_refund` enforces address consistency only when `deposit_msg.refund_address` is already set:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [1](#0-0) 

When `deposit_msg.refund_address` is `None`, the caller-supplied `refund_address` is stored verbatim in the `RefundRequest` with no identity check:

```rust
let refund_request = RefundRequest {
    ...
    refund_address,   // ← attacker-controlled
    ...
};
self.data_mut()
    .refund_requests
    .insert(utxo_storage_key, refund_request.into());
``` [2](#0-1) 

The `request_refund_callback` also blocks duplicate requests for the same UTXO:

```rust
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [3](#0-2) 

So the first caller wins. The `DepositMsg` and the on-chain transaction proof are both public, meaning any NEAR account can race to submit `request_refund` for any unfinalized deposit UTXO.

The system acknowledges this risk by applying a longer `unsafe_refund_timelock_sec` for the no-`refund_address` case:

```rust
} else {
    // Refund address supplied by caller of `request_refund`: longer
    // timelock to give DAO/Operator time to reject suspicious requests.
    config.unsafe_refund_timelock_sec
}
``` [4](#0-3) 

However, if the DAO/Operator is offline or unresponsive during that window, `execute_refund` is callable by anyone and will build a PSBT paying `refund_amount` to the attacker's address: [5](#0-4) 

The finalized refund PSBT is then signed by Chain Signatures and the BTC is irreversibly sent to the attacker. [6](#0-5) 

### Impact Explanation
The legitimate depositor permanently loses their BTC (deposit amount minus gas fee). Once `execute_refund` is signed and broadcast, the UTXO is marked in `verified_deposit_utxo`, blocking any future `verify_deposit` or re-execution of a corrected refund. The depositor has no recovery path. [7](#0-6) 

### Likelihood Explanation
The `DepositMsg` is public (it is hashed to derive the deposit address and must be shared with the relayer), and the deposit transaction is on-chain. Any NEAR account can construct a valid `request_refund` call. The attacker does not need to front-run in the mempool sense — they simply need to call `request_refund` before the depositor does, which could be at any point during the potentially long window between deposit confirmation and relayer finalization. The attack succeeds whenever the DAO/Operator fails to call `reject_refund` within `unsafe_refund_timelock_sec`. [8](#0-7) 

### Recommendation
Require `deposit_msg.refund_address` to be non-`None` for permissionless `request_refund` calls. When `refund_address` is absent from the `DepositMsg`, restrict `request_refund` to DAO/Operator roles only, or require the caller to provide a cryptographic proof of ownership of the supplied BTC address. This mirrors the fix applied in the Dinari protocol: return funds only to the party that committed to the parameters at order/deposit creation time.

### Proof of Concept
1. Alice deposits BTC to an address derived from `DepositMsg { recipient_id: "alice.near", refund_address: None }`. The relayer goes offline; `verify_deposit` is never called.
2. Attacker observes the confirmed deposit on-chain, reconstructs `deposit_msg`, and calls `request_refund(deposit_msg, "attacker_btc_addr", tx_bytes, vout, proof, None)`.
3. `request_refund_callback` stores `RefundRequest { refund_address: "attacker_btc_addr", ... }`.
4. Alice calls `request_refund` with her own address — it panics: `"Refund request already exists for this UTXO"`.
5. DAO/Operator is unresponsive. After `unsafe_refund_timelock_sec` elapses, attacker calls `execute_refund(utxo_storage_key, None)`.
6. Bridge builds a PSBT with output paying `refund_amount` to `"attacker_btc_addr"`, signs via Chain Signatures, and broadcasts. Alice's BTC is permanently lost. [9](#0-8)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L223-227)
```rust
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
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

**File:** contracts/satoshi-bridge/src/refund.rs (L544-547)
```rust
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
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
