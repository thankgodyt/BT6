### Title
Unauthorized Refund Address Substitution via Missing Caller Ownership Check in Refund Flow - (File: contracts/satoshi-bridge/src/refund.rs)

### Summary
The `internal_request_refund` function verifies that a deposit transaction is on-chain via the light client, but performs no check that the caller is the legitimate owner of the deposit (i.e., the `recipient_id` encoded in the `DepositMsg`). When a deposit's `DepositMsg` carries no pre-authorized `refund_address`, any unprivileged NEAR account can submit a refund request for that UTXO and supply an arbitrary attacker-controlled `refund_address`. After the `unsafe_refund_timelock_sec` elapses without operator rejection, the attacker can execute the refund and redirect the deposited BTC to their own address.

### Finding Description

`internal_request_refund` accepts a caller-supplied `deposit_msg` and `refund_address`:

```rust
pub(crate) fn internal_request_refund(
    &self,
    deposit_msg: DepositMsg,
    refund_address: String,
    ...
) -> Promise {
```

The only guard on `refund_address` is:

```rust
if let Some(msg_refund_address) = &deposit_msg.refund_address {
    require!(
        msg_refund_address == &refund_address,
        "refund_address does not match deposit_msg.refund_address"
    );
}
``` [1](#0-0) 

This guard is a no-op when `deposit_msg.refund_address` is `None` — the common case for ordinary deposits. The callback then verifies only that the transaction output script matches the bridge's derived deposit address for the given `deposit_msg`:

```rust
require!(
    deposit_script_pubkey == output.script_pubkey,
    "Output script_pubkey does not match deposit address"
);
``` [2](#0-1) 

There is no check that `env::predecessor_account_id()` equals `deposit_msg.recipient_id`. The `DepositMsg` is public information — it is hashed to derive the on-chain deposit address, so any observer of the Bitcoin chain can reconstruct it.

The `resolve_execute_refund_timelock` function confirms that non-privileged callers are permitted to call `execute_refund`; they simply face a longer timelock (`unsafe_refund_timelock_sec`) rather than being blocked:

```rust
} else {
    // Refund address supplied by caller of `request_refund`: longer
    // timelock to give DAO/Operator time to reject suspicious requests.
    config.unsafe_refund_timelock_sec
}
``` [3](#0-2) 

The protocol explicitly relies on operator intervention to reject malicious requests — there is no protocol-level ownership enforcement.

### Impact Explanation

An attacker who successfully executes this attack redirects the victim's deposited BTC to an attacker-controlled Bitcoin address. If the operator fails to call `internal_reject_refund` within `unsafe_refund_timelock_sec`, the BTC is permanently lost to the victim. This constitutes a **Critical** impact: significant theft of user funds. [4](#0-3) 

### Likelihood Explanation

The `DepositMsg` is fully public (it is hashed to derive the deposit address, and the hash is the UTXO storage key). Any attacker monitoring the Bitcoin mempool or NEAR chain can identify deposits without a pre-set `refund_address` and race to submit a malicious refund request before the legitimate owner does. The only mitigation is operator rejection during the timelock window, which is an off-chain, human-dependent process — not a protocol guarantee. Likelihood is **Medium**.

### Recommendation

Add an ownership check in `internal_request_refund` (or its public API wrapper) that requires `env::predecessor_account_id() == deposit_msg.recipient_id` before accepting a caller-supplied `refund_address`. Alternatively, require that all deposits encode a `refund_address` at deposit time (making the `None` branch unreachable for refunds), or restrict `request_refund` to the `recipient_id` or a whitelisted relayer acting on their behalf.

### Proof of Concept

1. Alice deposits 1 BTC to the bridge using a `DepositMsg { recipient_id: "alice.near", refund_address: None, ... }`. The deposit address is derived from this message and is publicly visible on-chain.
2. The deposit is not yet minted (e.g., the relayer has not submitted a proof, or the deposit amount is below the minimum).
3. Attacker Bob reconstructs Alice's `DepositMsg` from the Bitcoin transaction and calls `request_refund(deposit_msg=Alice's msg, refund_address="attacker_btc_addr", tx_bytes=..., vout=0, proof=...)` with sufficient attached NEAR for storage.
4. The light client verifies the transaction; `request_refund_callback` verifies the output script matches Alice's deposit address. No check is made that Bob is Alice. The refund request is stored with `refund_address = "attacker_btc_addr"`.
5. After `unsafe_refund_timelock_sec` elapses (assuming the operator does not call `reject_refund`), Bob calls `execute_refund`. The bridge constructs a Bitcoin transaction paying 1 BTC (minus gas fee) to `"attacker_btc_addr"` and submits it for MPC signing.
6. Alice's 1 BTC is permanently redirected to Bob. [5](#0-4) [6](#0-5)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L187-196)
```rust
    pub(crate) fn internal_reject_refund(&mut self, utxo_storage_key: String) {
        require!(
            self.data_mut()
                .refund_requests
                .remove(&utxo_storage_key)
                .is_some(),
            "Refund request not found"
        );
        Event::RefundRejected { utxo_storage_key }.emit();
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L223-228)
```rust
        } else {
            // Refund address supplied by caller of `request_refund`: longer
            // timelock to give DAO/Operator time to reject suspicious requests.
            config.unsafe_refund_timelock_sec
        }
    }
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
