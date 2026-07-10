### Title
Unprivileged Caller Can Register Arbitrary BTC Refund Address for Any Deposit, Redirecting Stuck Funds — (File: `contracts/satoshi-bridge/src/refund.rs`, `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`request_refund` imposes no check that the caller is the `recipient_id` embedded in `deposit_msg`. Any unprivileged NEAR account that knows a victim's `deposit_msg` (public information) can register themselves as the refund recipient for that deposit, supplying their own BTC address. After the `unsafe_refund_timelock_sec` elapses, the same attacker can call `execute_refund` to redirect the victim's stuck BTC to their own wallet.

---

### Finding Description

`request_refund` is a public, permissionless entry point: [1](#0-0) 

It accepts a caller-supplied `deposit_msg` (which encodes the intended `recipient_id`) and a separate `refund_address`. The only guard on `refund_address` is: [2](#0-1) 

This guard only fires when `deposit_msg.refund_address` is already set. When it is `None` — the common case for standard deposits — the caller may supply **any** BTC address. There is no check that `env::predecessor_account_id() == deposit_msg.recipient_id`.

The callback that stores the request also performs no caller-identity check: [3](#0-2) 

`execute_refund` is equally permissionless: [4](#0-3) 

The `deposit_msg` is public: it is the input to `get_user_deposit_address` and is broadcast by relayers when submitting proofs. An attacker can reconstruct it from on-chain events or by observing the deposit address derivation: [5](#0-4) 

---

### Impact Explanation

An attacker who front-runs (or races) the legitimate user's `request_refund` call stores their own BTC address as `refund_address` for the victim's UTXO. The duplicate-request guard then blocks the legitimate user: [6](#0-5) 

After `unsafe_refund_timelock_sec` elapses, the attacker calls `execute_refund`, which builds a PSBT paying the attacker's address and routes it through MPC signing: [7](#0-6) 

The victim's BTC is permanently redirected. This constitutes a **significant theft of user funds** — matching the "Medium: attacker-triggered temporary or permanent locking / redirection of bridged funds" impact tier, and potentially Critical if the operator does not reject in time.

---

### Likelihood Explanation

- `deposit_msg` is public: it is emitted in `LogDepositAddress` events and passed openly to relayer calls.
- `request_refund` and `execute_refund` require no special role.
- The only mitigation is operator rejection during `unsafe_refund_timelock_sec`; if operators are offline or slow, the attack succeeds silently.
- The attacker needs only NEAR gas and knowledge of the victim's `deposit_msg`.

---

### Recommendation

Add a caller-identity check inside `internal_request_refund` (or its callback) that requires `env::predecessor_account_id() == deposit_msg.recipient_id` when `deposit_msg.refund_address` is `None`. Alternatively, restrict `request_refund` to the `recipient_id` or to trusted relayers, and require that the `refund_address` be pre-committed in `deposit_msg` for permissionless calls.

---

### Proof of Concept

1. Victim deposits BTC; their `deposit_msg` has `recipient_id = victim.near`, `refund_address = None`. The deposit is never finalized (relayer failure).
2. Attacker observes the `LogDepositAddress` event, reconstructing `deposit_msg`.
3. Attacker calls:
   ```
   request_refund(
     deposit_msg = <victim's deposit_msg>,
     refund_address = "attacker_btc_address",
     tx_bytes = <victim's deposit tx>,
     vout = 0,
     proof = <valid inclusion proof>,
     gas_fee = None
   )
   ```
4. `request_refund_callback` verifies the proof and stores the request with `refund_address = attacker_btc_address`. [8](#0-7) 
5. Victim attempts `request_refund` — panics with "Refund request already exists for this UTXO". [6](#0-5) 
6. After `unsafe_refund_timelock_sec`, attacker calls `execute_refund(utxo_storage_key)`. MPC signs a transaction paying `attacker_btc_address`. Victim's BTC is stolen.

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

**File:** contracts/satoshi-bridge/src/refund.rs (L315-345)
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
