### Title
Unvalidated `refund_address` Committed to State in `request_refund` Permanently Blocks Refund Finalization — (File: `contracts/satoshi-bridge/src/refund.rs`)

### Summary

`request_refund` stores a `RefundRequest` containing a caller-supplied `refund_address` string without validating it as a syntactically correct BTC/ZEC address for the configured chain. The stored address is immutable — no update path exists. When `execute_refund` is later called, `build_refund_output` unconditionally panics on an invalid address, making the refund permanently un-executable. Because the duplicate-key guard blocks any second `request_refund` for the same UTXO, the stuck state can only be cleared by a DAO/Operator `reject_refund` call.

### Finding Description

**Root cause — no address validation at commit time:**

In `request_refund_callback` (the state-writing callback), the `refund_address` string is stored verbatim into `refund_requests` with zero format validation:

```rust
// refund.rs:564-578
let refund_request = RefundRequest {
    ...
    refund_address,          // ← stored as-is, never parsed
    ...
};
self.data_mut()
    .refund_requests
    .insert(utxo_storage_key, refund_request.into());
``` [1](#0-0) 

**Finalization panics on the stored address:**

`execute_refund` → `internal_execute_refund` (Bitcoin) or `execute_refund_callback` (Zcash) calls `build_refund_output`, which hard-panics if the address cannot be parsed:

```rust
// refund.rs:296-297
let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
    .expect("Invalid refund address");
``` [2](#0-1) 

Because NEAR transactions are atomic, the panic reverts the call without touching `refund_requests`, so the invalid `RefundRequest` persists unchanged.

**No overwrite path:**

The duplicate guard in `request_refund_callback` prevents any second submission for the same UTXO:

```rust
// refund.rs:544-547
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
``` [3](#0-2) 

There is no `update_refund_address` or equivalent function anywhere in the contract.

**Attacker-controlled entry path (front-run griefing):**

When a user's `DepositMsg` has `refund_address: None`, the `refund_address` parameter of `request_refund` is entirely caller-supplied and is only checked for consistency with `deposit_msg.refund_address` (which is `None`, so the check is skipped):

```rust
// refund.rs:154-159
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [4](#0-3) 

An attacker who observes the `LogDepositAddress` event (which emits the full `DepositMsg`) and the corresponding BTC transaction on-chain can call `request_refund` before the legitimate user, supplying a syntactically invalid or wrong-network address (e.g., a Zcash address on a Bitcoin deployment, or a raw garbage string). The `RefundRequest` is committed with the bad address, and the legitimate user's subsequent `request_refund` call is rejected with "Refund request already exists for this UTXO". [5](#0-4) 

### Impact Explanation

The user's deposit UTXO is locked in the bridge's MPC-controlled address. The refund path is permanently broken for that UTXO until a DAO/Operator calls `reject_refund`. If the relayer is also unavailable to call `verify_deposit`, the user's BTC is fully inaccessible. Even in the best case (relayer available), the user is forced to depend on privileged operator intervention to unblock their funds — a stuck bridge state requiring operator intervention.

This matches the **Medium** allowed impact: *"Harmful smart-contract behavior without direct funds theft, including … stuck bridge state requiring operator intervention."*

### Likelihood Explanation

- All inputs needed for the attack (`DepositMsg` from `LogDepositAddress` event, `tx_bytes`/`vout` from the public Bitcoin mempool/blockchain) are publicly observable.
- `request_refund` is callable by any NEAR account (confirmed by test coverage where unprivileged accounts such as `"alice"` call it successfully).
- The only cost to the attacker is the storage deposit (`required_balance_for_request_refund()`), which is a small, fixed NEAR amount.
- The attack window is the period between the BTC transaction confirming and the legitimate user calling `request_refund` — a realistic front-run window.

### Recommendation

Validate `refund_address` against the configured chain inside `request_refund_callback`, before storing the `RefundRequest`. Reuse the same `Address::parse` call already present in `build_refund_output`:

```rust
// In request_refund_callback, before constructing RefundRequest:
crate::network::Address::parse(&refund_address, config.chain.clone())
    .expect("Invalid refund_address for configured chain");
```

This mirrors the recommendation from the Linea report: move all validation into the submission step so that invalid data is rejected before it is committed to immutable state.

### Proof of Concept

1. Alice calls `get_user_deposit_address(DepositMsg { recipient_id: "alice", refund_address: None, … })`. The `LogDepositAddress` event is emitted with the full `DepositMsg`.
2. Alice sends 100 000 sat to the derived BTC deposit address. The transaction is confirmed on Bitcoin.
3. Attacker observes the `DepositMsg` from the event and the BTC transaction from the blockchain.
4. Attacker calls `request_refund(deposit_msg, refund_address="INVALID_GARBAGE", tx_bytes, vout, proof, None)` with the required storage deposit attached.
5. `request_refund_callback` passes all checks (light-client proof valid, script matches, no duplicate yet) and stores `RefundRequest { refund_address: "INVALID_GARBAGE", … }`.
6. Alice calls `request_refund(…)` — reverts with `"Refund request already exists for this UTXO"`.
7. After the timelock, anyone calls `execute_refund(utxo_storage_key)`. `build_refund_output` panics: `"Invalid refund address"`. The `RefundRequest` is unchanged.
8. Alice's BTC is stuck. Recovery requires DAO/Operator to call `reject_refund(utxo_storage_key)`. [6](#0-5) [7](#0-6)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L294-300)
```rust
    pub(crate) fn build_refund_output(&self, refund_address: &str, refund_amount: u128) -> TxOut {
        let config = self.internal_config();
        let refund_addr = crate::network::Address::parse(refund_address, config.chain.clone())
            .expect("Invalid refund address");
        let refund_script_pubkey = refund_addr
            .script_pubkey()
            .expect("Invalid refund script_pubkey");
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
