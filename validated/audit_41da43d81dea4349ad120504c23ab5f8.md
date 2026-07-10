### Title
Unprotected Refund-Request Slot Allows Front-Running to Redirect or Permanently Block User Refunds - (File: `contracts/satoshi-bridge/src/refund.rs`)

### Summary
`internal_request_refund` does not lock the UTXO's refund-request slot before issuing the cross-contract call to the light client. Because NEAR cross-contract calls are not atomic, a second concurrent `request_refund` for the same UTXO can race the first one and win the slot, inserting an attacker-controlled `refund_address`. The legitimate user's callback then panics and their storage deposit is unrecoverable. If the DAO does not reject the winning request before `unsafe_refund_timelock_sec` elapses, the attacker can execute the refund and redirect the underlying BTC to their own address.

### Finding Description

`internal_request_refund` (refund.rs L137–184) performs all validation and then fires a cross-contract call to the BTC light client, deferring state mutation entirely to the callback: [1](#0-0) 

No "pending" marker is written to `refund_requests` or `verified_deposit_utxo` before this call. The slot remains open until `request_refund_callback` runs in a later block.

The callback's duplicate-check (the only guard) is: [2](#0-1) 

This check is correct in isolation, but it is a read of unprotected shared state that can be lost to a concurrent writer — the exact pattern flagged in the reference report. Because `deposit_msg`, `tx_bytes`, and the Merkle proof are all public Bitcoin data, any observer can reconstruct a valid `request_refund` call for the same UTXO with an arbitrary `refund_address`.

The `refund_address` override is only blocked when `deposit_msg.refund_address` is `Some`: [3](#0-2) 

When `deposit_msg.refund_address` is `None` (the common case for users who do not pre-authorize an address), the attacker may supply any Bitcoin address.

The attacker's callback writes first: [4](#0-3) 

The victim's callback then panics on the duplicate check. Because the panic occurs inside a callback (a separate NEAR receipt), the victim's original attached storage deposit — already transferred to the contract in the parent call — is not returned: [5](#0-4) 

There is no recovery path for this deposit once the callback panics.

The CLAUDE.md security invariant that is violated is explicit:

> Mutate state (mark UTXO used, update balances) **BEFORE** cross-contract calls. [6](#0-5) 

### Impact Explanation

**Immediate (Medium):** The attacker's refund request occupies the slot. The victim cannot submit a new request (duplicate check blocks it). The victim's NEAR storage deposit is permanently stuck in the contract. The victim's BTC is locked until the DAO rejects the attacker's request.

**Escalated (Critical, if DAO does not act):** After `unsafe_refund_timelock_sec` elapses, the attacker calls `execute_refund`, which builds a refund PSBT paying `attacker_btc_address` and initiates MPC signing: [7](#0-6) 

The victim's BTC is then sent to the attacker's Bitcoin address. This constitutes unauthorized release of underlying BTC — a Critical bridge impact.

### Likelihood Explanation

- `deposit_msg.refund_address = None` is the default for ordinary bridge users; the attack surface is broad.
- All inputs (`deposit_msg`, `tx_bytes`, Merkle proof) are public Bitcoin/NEAR data; no privileged access is required.
- NEAR receipt ordering is deterministic per shard; an attacker who submits their `request_refund` in the same block as the victim's call has a realistic chance of having their callback processed first.
- The `unsafe_refund_timelock_sec` window is the only mitigation, and it depends entirely on DAO liveness and vigilance — not on protocol enforcement.

### Recommendation

Write a "pending" sentinel into `refund_requests` (or a dedicated `pending_refund_utxos` set) **before** the light-client cross-contract call, inside `internal_request_refund`. If `request_refund_callback` fails (light-client rejection or duplicate), remove the sentinel and refund the attached deposit. This mirrors the CLAUDE.md invariant: mutate state before cross-contract calls.

### Proof of Concept

1. User deposits BTC to an address derived from `deposit_msg` where `deposit_msg.refund_address = None`.
2. User calls `request_refund(deposit_msg, user_btc_addr, tx_bytes, vout, proof)` — TX₁.
3. TX₁ fires a cross-contract call to the light client; the `refund_requests` slot for this UTXO remains empty.
4. Attacker observes TX₁ on-chain, reconstructs all public parameters, and submits `request_refund(deposit_msg, attacker_btc_addr, tx_bytes, vout, proof)` — TX₂ — in the same or next block.
5. TX₂'s callback (`request_refund_callback`) executes first; it passes both guards (slot empty, UTXO not yet verified) and inserts `RefundRequest { refund_address: attacker_btc_addr, … }`.
6. TX₁'s callback executes next; the duplicate check at L544–547 panics. The victim's storage deposit is not returned.
7. The victim cannot re-submit (slot occupied). The DAO must actively reject the attacker's request within `unsafe_refund_timelock_sec`.
8. If the DAO does not act, the attacker calls `execute_refund`, which builds and signs a refund PSBT paying `attacker_btc_addr`, and the victim's BTC is transferred to the attacker. [8](#0-7) [9](#0-8)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L315-322)
```rust
    pub(crate) fn finalize_refund_with_psbt(
        &mut self,
        caller: AccountId,
        mut refund_request: RefundRequest,
        psbt: PsbtWrapper,
        refund_amount: u128,
        utxo_storage_key: String,
    ) {
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

**File:** CLAUDE.md (L73-75)
```markdown
- Mutate state (mark UTXO used, update balances) BEFORE cross-contract calls
- Create and emit events AFTER all state mutations complete
- **Cross-contract calls are NOT atomic:** Each callback is a separate transaction - must manually rollback state in callback if external call fails
```
