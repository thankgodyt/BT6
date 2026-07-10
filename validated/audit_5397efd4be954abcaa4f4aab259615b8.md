### Title
Front-Running `request_refund` Allows Attacker to Redirect BTC Refund to Attacker-Controlled Address — (File: `contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

The `request_refund` entry point is fully permissionless and does not bind the stored refund destination to the submitter's identity. When `deposit_msg.refund_address` is `None`, any caller may race a legitimate user's submission and register the same UTXO's refund request with an attacker-controlled BTC address. Because only one refund request can exist per UTXO, the legitimate user's callback is permanently blocked, and the BTC refund is directed to the attacker's address once the timelock elapses.

---

### Finding Description

`request_refund` is a `#[payable]` public function with no caller-identity restriction: [1](#0-0) 

It delegates to `internal_request_refund`, which enforces a `refund_address` match **only when** `deposit_msg.refund_address` is already set: [2](#0-1) 

When `deposit_msg.refund_address` is `None` (the common case for users who did not pre-authorize a BTC address at deposit time), the caller-supplied `refund_address` is accepted without any ownership check and stored verbatim in the `RefundRequest`: [3](#0-2) 

The callback enforces a hard uniqueness constraint — only one request per UTXO is allowed: [4](#0-3) 

Once a request is stored, `execute_refund` is also permissionless (no caller restriction beyond the timelock and pause check): [5](#0-4) 

The BTC output is built directly from the stored `refund_address`, not from the executor's identity: [6](#0-5) 

---

### Impact Explanation

An attacker who wins the race registers the refund request with their own BTC address. The legitimate user's `request_refund_callback` panics with `"Refund request already exists for this UTXO"`, consuming their attached NEAR storage deposit. The attacker then calls `execute_refund` after `unsafe_refund_timelock_sec` elapses, and the MPC pipeline constructs and signs a Bitcoin transaction paying the attacker's address. If the DAO/Operator does not reject the request within the timelock window, the user's BTC is permanently transferred to the attacker. Even if the operator intervenes, the user's funds are temporarily locked and their NEAR deposit is lost, requiring operator action to restore access.

This matches the **Medium** allowed impact (attacker-triggered temporary locking of bridged funds requiring operator intervention) with escalation to **Critical** (significant loss/theft of user BTC) if the operator fails to act within `unsafe_refund_timelock_sec`.

---

### Likelihood Explanation

The BTC blockchain is fully public. An attacker can monitor it for deposits that have not yet been finalized via `verify_deposit`. The `deposit_msg` fields needed to reconstruct the UTXO key are derivable from on-chain data. The attacker needs only to submit `request_refund` with their own BTC address before the legitimate user does — no privileged access, leaked key, or majority attack is required. The only cost is the NEAR storage deposit (`required_balance_for_request_refund`), which is a small, fixed amount.

---

### Recommendation

- **Short term:** When `deposit_msg.refund_address` is `None`, bind the stored `refund_address` to the submitter's NEAR account identity (e.g., require the caller to prove ownership of the BTC address, or record `predecessor_account_id` and restrict `execute_refund` to that account).
- **Long term:** Require `deposit_msg.refund_address` to be set (non-`None`) for all permissionless refund requests, eliminating the caller-supplied address path entirely. Alternatively, use a commit-reveal scheme so the refund address cannot be observed and front-run before it is committed on-chain.

---

### Proof of Concept

1. Alice sends BTC to a deposit address derived from `deposit_msg` (with `deposit_msg.refund_address = None`). The deposit is never finalized via `verify_deposit`.
2. Bob monitors the BTC blockchain, observes the unfinalized deposit, and reconstructs `deposit_msg`, `tx_bytes`, `vout`, and the Merkle proof.
3. Bob calls `request_refund(deposit_msg, bob_btc_address, tx_bytes, vout, proof, None)` before Alice.
4. Bob's `request_refund_callback` succeeds; the `RefundRequest` is stored with `refund_address = bob_btc_address`.
5. Alice calls `request_refund(deposit_msg, alice_btc_address, tx_bytes, vout, proof, None)`. Her callback panics: `"Refund request already exists for this UTXO"`. Alice loses her attached NEAR deposit.
6. Alice cannot submit another request for the same UTXO.
7. After `unsafe_refund_timelock_sec` elapses (and if the DAO does not reject), Bob calls `execute_refund(utxo_storage_key, None)`.
8. `finalize_refund_with_psbt` builds a Bitcoin transaction paying `bob_btc_address` and submits it to the MPC signing pipeline. [7](#0-6) 

Alice's BTC is sent to Bob's address. The only recovery path requires DAO/Operator to reject Bob's request within the timelock window — an operational dependency that is not guaranteed.

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L508-535)
```rust
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

**File:** contracts/satoshi-bridge/src/refund.rs (L154-159)
```rust
        if let Some(msg_refund_address) = &deposit_msg.refund_address {
            require!(
                msg_refund_address == &refund_address,
                "refund_address does not match deposit_msg.refund_address"
            );
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

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
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
