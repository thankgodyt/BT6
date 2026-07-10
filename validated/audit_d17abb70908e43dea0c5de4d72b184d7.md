### Title
Attacker Can Front-Run `request_refund` With Malicious `refund_address` When `deposit_msg.refund_address` Is `None`, Causing DoS and Potential BTC Theft - (`contracts/satoshi-bridge/src/refund.rs`)

### Summary

When a user deposits BTC without pre-authorizing a refund address (`deposit_msg.refund_address = None`), any NEAR account can call `request_refund` with the same `tx_bytes`/`vout`/`deposit_msg` but substitute an attacker-controlled BTC address as `refund_address`. Because the refund slot is keyed by `utxo_storage_key` (`{tx_id}@{vout}`) and the first writer wins, the attacker permanently occupies the slot, causing the legitimate user's call to fail with "Refund request already exists for this UTXO." If the DAO does not reject the malicious request within `unsafe_refund_timelock_sec`, the bridge's MPC pipeline will sign and broadcast a refund transaction sending the user's BTC to the attacker's address.

### Finding Description

`request_refund` is publicly callable (the `#[trusted_relayer]` attribute on the impl block at line 480 is a configuration marker; individual method-level gating is absent for `request_refund` and `execute_refund`, as confirmed by the doc statement "After the timelock period, **anyone** can call `execute_refund`"). [1](#0-0) 

Inside `internal_request_refund`, when `deposit_msg.refund_address` is `None`, the `refund_address` parameter is accepted verbatim from the caller with no ownership check: [2](#0-1) 

After Light Client verification, `request_refund_callback` stores the request keyed by `utxo_storage_key` and rejects any subsequent request for the same UTXO: [3](#0-2) 

The stored `RefundRequest` contains the attacker-supplied `refund_address` with no binding to the original depositor: [4](#0-3) 

Once stored, `execute_refund` builds a PSBT that pays out to `refund_request.refund_address` — the attacker's BTC address: [5](#0-4) 

The `unsafe_refund_timelock_sec` path (applied when `deposit_msg.refund_address` is `None`) gives the DAO extra time to reject, but does not prevent the DoS and relies entirely on DAO vigilance to prevent theft: [6](#0-5) 

### Impact Explanation

**DoS (certain):** The legitimate user's `request_refund` call fails with "Refund request already exists for this UTXO." The user cannot reclaim their BTC until the DAO rejects the malicious request. The attacker can repeat the front-run on every retry, permanently blocking the user.

**BTC theft (conditional):** If the DAO does not reject the malicious request within `unsafe_refund_timelock_sec`, `execute_refund` is called, the MPC network signs the PSBT, and the bridge broadcasts a transaction sending the user's BTC to the attacker's address. This constitutes a direct loss of user funds locked in the bridge.

This matches the allowed impact: *"Medium. Attacker-triggered temporary locking of bridged funds"* (DoS path) and *"Critical. Significant loss or theft of user funds"* (theft path if DAO fails to act).

### Likelihood Explanation

All inputs needed to mount the attack are public:
- `tx_bytes` and `vout` are visible on the Bitcoin blockchain.
- `deposit_msg` (including `recipient_id`) is emitted as a `LogDepositAddress` event when `get_user_deposit_address` is called. [7](#0-6) 

The attacker does not need to observe a NEAR mempool; they can simply race to call `request_refund` after spotting an unfinalized deposit on-chain. The only cost is the attached NEAR storage deposit, which is non-refundable but small.

### Recommendation

1. **Bind `refund_address` to the depositor at deposit time.** Require `deposit_msg.refund_address` to be set (non-`None`) before a refund request can be submitted. This makes the address immutable and verified against the on-chain deposit path.

2. **Alternatively, record the caller as the refund request owner** and restrict `execute_refund` to the owner (or DAO/Operator), preventing an attacker from occupying the slot with a foreign address.

3. **At minimum, add a caller-ownership check in `request_refund_callback`** so that only the account whose `recipient_id` matches `deposit_msg.recipient_id` (or a whitelisted relayer acting on their behalf) can register a refund address when `deposit_msg.refund_address` is `None`.

### Proof of Concept

1. Alice deposits 100,000 sat to a bridge address derived from `DepositMsg { recipient_id: "alice.near", refund_address: None }`. The `LogDepositAddress` event is emitted on NEAR.
2. `verify_deposit` is never called (relayer is down).
3. Eve observes the Bitcoin transaction and the NEAR event. She calls:
   ```
   request_refund(
     deposit_msg = { recipient_id: "alice.near", refund_address: None },
     refund_address = "eve_btc_address",
     tx_bytes = <alice's tx>,
     vout = 0,
     proof = <valid proof>,
   )
   ```
   attaching the required NEAR storage deposit.
4. The Light Client validates the proof. `request_refund_callback` stores `RefundRequest { refund_address: "eve_btc_address", ... }` under `utxo_storage_key`.
5. Alice calls `request_refund` with `refund_address = "alice_btc_address"`. It fails: "Refund request already exists for this UTXO."
6. After `unsafe_refund_timelock_sec` elapses (if DAO does not reject), Eve or anyone calls `execute_refund`. The bridge builds a PSBT paying `"eve_btc_address"`, the MPC signs it, and Alice's 100,000 sat are sent to Eve. [8](#0-7) [9](#0-8)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L462-472)
```rust
    pub fn get_user_deposit_address(&self, deposit_msg: DepositMsg) -> String {
        let path = get_deposit_path(&deposit_msg);
        let deposit_address = self.generate_utxo_chain_address(&path).to_string();
        Event::LogDepositAddress {
            deposit_msg,
            path,
            deposit_address: deposit_address.clone(),
        }
        .emit();
        deposit_address
    }
```

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

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
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

**File:** contracts/satoshi-bridge/src/refund.rs (L315-372)
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
```

**File:** contracts/satoshi-bridge/src/refund.rs (L496-547)
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

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L30-42)
```rust
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
```
