### Title
Unauthenticated `request_refund` Allows Any Caller to Register an Attacker-Controlled BTC Refund Address for a Victim's Deposit — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`request_refund` carries no check that the caller is the `deposit_msg.recipient_id`. When a deposit was made without a pre-authorized `refund_address` (`deposit_msg.refund_address == None`), any NEAR account can call `request_refund` for that deposit and supply an attacker-controlled BTC address. After `unsafe_refund_timelock_sec` elapses, `execute_refund` (also open to any caller) will route the victim's BTC to the attacker's address.

---

### Finding Description

`request_refund` is the public entry point for initiating a BTC refund for a deposit that was never finalized via `verify_deposit`.

```
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn request_refund(
    &mut self,
    deposit_msg: DepositMsg,
    refund_address: String,
    ...
    gas_fee: Option<U128>,
) -> Promise {
    if gas_fee.is_some() {
        // Only DAO or Operator can specify custom gas_fee
    }
    self.internal_request_refund(deposit_msg, refund_address, ...)
}
```

The only caller-identity check in the entire function is the optional `gas_fee` guard. There is no check that `env::predecessor_account_id() == deposit_msg.recipient_id`. [1](#0-0) 

Inside `internal_request_refund`, the only constraint on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [2](#0-1) 

When `deposit_msg.refund_address` is `None` — the common case for users who did not embed a BTC return address at deposit time — this branch is skipped entirely. The caller-supplied `refund_address` is accepted verbatim and stored in the `RefundRequest`. [3](#0-2) 

`execute_refund` is also open to any caller after the timelock:

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
``` [4](#0-3) 

`internal_execute_refund` (Bitcoin path) builds the refund PSBT directly to `refund_request.refund_address` — the address stored at `request_refund` time — and submits it to MPC for signing: [5](#0-4) 

The `unsafe_refund_timelock_sec` is the only mitigation: it gives DAO/Operator a window to call `reject_refund`. But `reject_refund` itself requires a privileged role, and if the operator is offline, slow, or the timelock window is short, the attacker wins the race. [6](#0-5) 

---

### Impact Explanation

After `unsafe_refund_timelock_sec` elapses without a DAO/Operator rejection, the attacker calls `execute_refund`. The bridge's MPC pipeline signs a Bitcoin transaction that pays the victim's deposited BTC to the attacker's address. The victim's funds are permanently lost. This is a direct, on-chain theft of user BTC mediated by the bridge's own MPC signing infrastructure.

Impact classification: **Critical** — significant loss of user funds.

---

### Likelihood Explanation

- `deposit_msg` is submitted as a NEAR transaction argument to `get_user_deposit_address` (a public view call), making it fully observable on-chain by any party.
- Deposits without a pre-authorized `refund_address` are the common case for standard bridge users.
- The attacker only needs to pay the `required_balance_for_request_refund` storage deposit (non-refundable anti-spam fee), which is economically rational if the victim's BTC value exceeds it.
- The attack window is the entire `unsafe_refund_timelock_sec` period. Any gap in DAO/Operator monitoring (downtime, key rotation, governance dispute) is sufficient.
- `execute_refund` has no access control, so the attacker can trigger it themselves the moment the timelock expires.

Likelihood: **Medium** — requires the DAO/Operator to miss the rejection window, but the attack is fully permissionless and economically incentivized for large deposits.

---

### Recommendation

Add an ownership check in `request_refund` that enforces `env::predecessor_account_id() == deposit_msg.recipient_id` when `deposit_msg.refund_address` is `None`. Privileged roles (DAO, Operator, RefundOperator) may be exempted to allow operator-assisted refunds. Alternatively, require that `refund_address` always be embedded in `deposit_msg` at deposit time (i.e., reject `request_refund` when `deposit_msg.refund_address` is `None` and the caller is not privileged), so the refund destination is always pre-authorized by the depositor.

---

### Proof of Concept

1. Victim calls `get_user_deposit_address({recipient_id: "victim.near", refund_address: None})` — the `deposit_msg` is visible in the NEAR transaction history.
2. Victim sends BTC to the returned deposit address. `verify_deposit` is never called (relayer down, user changed mind, etc.).
3. Attacker submits:
   ```
   request_refund(
     deposit_msg = {recipient_id: "victim.near", refund_address: None, ...},
     refund_address = "attacker_btc_address",
     tx_bytes = <victim's deposit tx>,
     vout = 0,
     proof = <valid merkle proof>,
     gas_fee = None
   )
   ```
4. `request_refund_callback` verifies the BTC transaction is valid and the deposit address matches `deposit_msg`. No caller identity check occurs. A `RefundRequest` is stored with `refund_address = "attacker_btc_address"`. [7](#0-6) 
5. DAO/Operator fails to call `reject_refund` before `unsafe_refund_timelock_sec` elapses.
6. Attacker calls `execute_refund(utxo_storage_key)`. The bridge builds a PSBT paying the victim's BTC to `"attacker_btc_address"` and submits it to MPC for signing.
7. The signed transaction is broadcast. Victim's BTC is permanently redirected to the attacker.

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
