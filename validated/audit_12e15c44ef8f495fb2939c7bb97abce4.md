### Title
Frontrunning `request_refund` Blocks Victim's Refund and Loses Their NEAR Storage Deposit — (File: `contracts/satoshi-bridge/src/refund.rs`, `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary
`request_refund` performs no duplicate-key check before initiating its cross-contract Light Client verification call. The duplicate check only fires inside `request_refund_callback`, after the caller's attached NEAR storage deposit has already been consumed by the contract. An unprivileged attacker who observes a pending `request_refund` transaction can frontrun it with the same UTXO key (`{txid}@{vout}`) and a different `refund_address`, permanently blocking the victim's refund request and causing the victim to lose their non-refundable NEAR storage deposit. When `deposit_msg.refund_address` is `None`, the attacker can additionally redirect the BTC refund to their own address.

---

### Finding Description

`request_refund` is a public, payable function. Its entry point `internal_request_refund` performs only three checks before dispatching the cross-contract call: [1](#0-0) 

None of these checks test whether a refund request for the same UTXO already exists. The duplicate guard is deferred entirely to `request_refund_callback`: [2](#0-1) 

By the time this callback executes, the victim's attached NEAR deposit has already been transferred to the contract (NEAR does not auto-refund deposits when a callback panics). The callback panics with `"Refund request already exists for this UTXO"`, and the deposit is silently retained by the contract with no recovery path.

The UTXO storage key is deterministic and public — it is simply `{txid}@{vout}`: [3](#0-2) 

Both the BTC transaction ID and the vout are visible on the Bitcoin blockchain before any NEAR transaction is submitted, making the key trivially predictable. An attacker can frontrun with the same `deposit_msg`, `tx_bytes`, `vout`, and `proof`, but substitute their own `refund_address`. The `refund_address` substitution is only blocked when `deposit_msg.refund_address` is already set: [4](#0-3) 

When `deposit_msg.refund_address` is `None` (the common case for users who did not pre-authorize a refund address), the attacker's chosen address is stored verbatim in the `RefundRequest`: [5](#0-4) 

After the `unsafe_refund_timelock_sec` elapses, `execute_refund` is callable by anyone (no role restriction on the function itself): [6](#0-5) 

This routes the BTC to the attacker's address via `finalize_refund_with_psbt`, which uses `refund_request.refund_address` directly: [7](#0-6) 

---

### Impact Explanation

**Unconditional griefing + NEAR deposit loss**: Every `request_refund` call for a UTXO that already has a pending request will panic in the callback. The victim's attached NEAR storage deposit (sized to cover up to ~2 NEAR for large transactions) is permanently lost with no recovery mechanism in the callback.

**Conditional BTC theft**: When `deposit_msg.refund_address` is `None`, the attacker's `refund_address` is stored. If the DAO/Operator does not reject the request within `unsafe_refund_timelock_sec`, anyone can call `execute_refund` and the user's deposited BTC is sent to the attacker's Bitcoin address — a direct theft of bridged funds.

The DAO's ability to reject is a mitigation, not a fix: it requires active monitoring and timely intervention, and the victim's NEAR deposit is lost regardless.

---

### Likelihood Explanation

- The UTXO key (`txid@vout`) is fully public from the Bitcoin blockchain before any NEAR call is made.
- NEAR transaction mempools are observable; the attacker can also preemptively submit for any unfinalized deposit they spot on-chain.
- The attacker's cost is only the NEAR gas and the storage deposit for their own `request_refund` call (which they lose if the DAO rejects, but the victim's deposit is already gone).
- No special privilege is required — any NEAR account can call `request_refund`.

---

### Recommendation

Add the duplicate-key check **before** the cross-contract call in `internal_request_refund`, so the function panics immediately (returning the attached deposit to the caller) if a request for the same UTXO already exists:

```rust
let utxo_storage_key = generate_utxo_storage_key(
    transaction.compute_txid().to_string(),
    u32::try_from(vout).unwrap_or_else(|_| env::panic_str("vout overflow")),
);
require!(
    !self.data().refund_requests.contains_key(&utxo_storage_key),
    "Refund request already exists for this UTXO"
);
require!(
    !self.data().verified_deposit_utxo.contains(&utxo_storage_key),
    "UTXO already verified via deposit"
);
```

This mirrors the existing callback checks but moves them to the synchronous entry point, before any deposit is consumed.

---

### Proof of Concept

1. Alice has an unfinalized BTC deposit with `txid = "abc123"`, `vout = 0`, and `deposit_msg.refund_address = None`. She calls `request_refund` with her BTC address as `refund_address`, attaching the required NEAR storage deposit.

2. Bob (attacker) observes Alice's pending NEAR transaction (or the unfinalized BTC UTXO on-chain). Bob calls `request_refund` with the identical `deposit_msg`, `tx_bytes`, `vout`, and `proof`, but substitutes his own BTC address as `refund_address`. Bob's call lands first.

3. Bob's `request_refund_callback` succeeds. The `refund_requests` map now contains key `"abc123@0"` pointing to Bob's BTC address.

4. Alice's `request_refund_callback` executes and panics at:
   ```
   require!(!self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO");
   ```
   Alice's attached NEAR deposit is not returned — it is retained by the contract.

5. Alice cannot resubmit (the key is occupied). She must wait for the DAO to notice and call `reject_refund` on Bob's request before she can try again — and she has already lost her NEAR deposit.

6. If the DAO does not act within `unsafe_refund_timelock_sec`, Bob calls `execute_refund("abc123@0", None)`. The bridge constructs a refund transaction paying Alice's BTC to Bob's address and submits it for MPC signing. Alice's deposited BTC is stolen.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L146-183)
```rust
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
```

**File:** contracts/satoshi-bridge/src/refund.rs (L323-325)
```rust
        let gas_fee = refund_request.gas_fee;
        let refund_address = refund_request.refund_address.clone();

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

**File:** contracts/satoshi-bridge/src/utils.rs (L16-23)
```rust
pub fn generate_utxo_storage_key(txid: String, vout: u32) -> String {
    format!(
        "{}{}{}",
        txid,
        UTXO_STORAGE_KEY_TAG,
        vout.to_string().as_str()
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
