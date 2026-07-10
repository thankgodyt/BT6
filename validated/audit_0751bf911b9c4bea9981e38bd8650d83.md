### Title
User-Controlled `gas_fee` Parameter Bypasses Protocol Refund Fee — (File: `contracts/satoshi-bridge/src/refund.rs`)

### Summary
The `request_refund` flow accepts a caller-supplied `gas_fee: Option<u128>` parameter that is stored verbatim in the `RefundRequest` and later used to compute the refund amount. The only validation is that the fee is strictly less than the deposit amount. A user can pass `Some(0)` to set the gas fee to zero, receiving a full refund of their deposit while the operator must absorb the on-chain BTC transaction cost out of pocket.

### Finding Description
In `contracts/satoshi-bridge/src/refund.rs`, `internal_request_refund` accepts a `gas_fee: Option<u128>` parameter and passes it through to the `#[private]` callback `request_refund_callback`.

Inside `request_refund_callback`, the fee is resolved as:

```rust
let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
require!(
    resolved_gas_fee < amount,
    "Gas fee must be less than deposit amount"
);
``` [1](#0-0) 

The only guard is `resolved_gas_fee < amount`. There is no minimum fee floor, no check that the caller-supplied value is `>= self.get_refund_gas_fee()`, and no whitelist or role restriction on who may supply a custom fee. The resolved fee is then stored directly in the `RefundRequest`:

```rust
let refund_request = RefundRequest {
    ...
    gas_fee: resolved_gas_fee,
    ...
};
``` [2](#0-1) 

Later, `refund_execution_inputs` computes the amount returned to the user as `amount - gas_fee`:

```rust
let refund_amount = refund_request
    .amount
    .checked_sub(refund_request.gas_fee)
    .expect("Deposit amount too small to cover gas fee");
``` [3](#0-2) 

Because `gas_fee` is user-controlled and unchecked against the protocol's configured minimum, any caller can set it to `Some(0)` and receive the full deposit amount as a refund, paying no fee to the operator.

### Impact Explanation
The operator (or protocol treasury) is responsible for paying the actual BTC network fee to broadcast the refund transaction. When `gas_fee = 0` is accepted, the operator subsidizes every such refund with no compensation. At scale, an attacker can repeatedly deposit small amounts and immediately request refunds with `gas_fee = Some(0)`, forcing the operator to pay BTC fees on every refund while the attacker recovers 100% of their deposit. This is a bypass of the bridge's fee/policy controls.

**Allowed impact matched:** Medium — Bypass of bridge limits or policies.

### Likelihood Explanation
The entry path is fully public and requires no privileged role. Any NEAR account that can submit a deposit transaction can call `request_refund` with `gas_fee = Some(0)`. The only prerequisite is a valid BTC deposit and a passing light-client proof, both of which are normal user actions. Likelihood is high.

### Recommendation
Enforce a minimum fee floor in `request_refund_callback`. If a caller-supplied `gas_fee` is provided, validate it is at least the protocol-configured minimum:

```rust
let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
let min_fee = self.get_refund_gas_fee();
require!(
    resolved_gas_fee >= min_fee,
    "gas_fee below protocol minimum"
);
require!(resolved_gas_fee < amount, "Gas fee must be less than deposit amount");
```

Alternatively, remove the `gas_fee` parameter from the public API entirely and always derive it from `self.get_refund_gas_fee()`, matching the pattern used when `None` is supplied.

### Proof of Concept
1. Alice deposits 10,000 sat to her bridge address and waits for confirmation.
2. Alice calls `request_refund(deposit_msg, refund_address, tx_bytes, vout, proof, gas_fee: Some(0))`.
3. `request_refund_callback` resolves `resolved_gas_fee = 0`. The check `0 < 10000` passes.
4. `RefundRequest { amount: 10000, gas_fee: 0, ... }` is stored.
5. After the timelock, `execute_refund` is called. `refund_execution_inputs` computes `refund_amount = 10000 - 0 = 10000`.
6. A refund PSBT paying Alice 10,000 sat is constructed and signed by MPC.
7. Alice receives 100% of her deposit; the operator pays the BTC network fee (~200–2000 sat) with no reimbursement.
8. Alice repeats this for every deposit, systematically draining the operator's BTC fee budget. [4](#0-3) [5](#0-4)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L280-283)
```rust
        let refund_amount = refund_request
            .amount
            .checked_sub(refund_request.gas_fee)
            .expect("Deposit amount too small to cover gas fee");
```

**File:** contracts/satoshi-bridge/src/refund.rs (L497-581)
```rust
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
