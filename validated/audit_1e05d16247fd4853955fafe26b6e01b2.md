The code path is fully traceable. Let me confirm the exact check in `request_refund_callback` and whether any operator recovery path exists for `unavailable_utxos`.

### Title
Below-minimum deposit permanently blocks `request_refund` via `verified_deposit_utxo` collision — (`contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

### Summary

`unavailable_utxo_callback` inserts a below-minimum UTXO into `verified_deposit_utxo` as replay protection. The same set is checked by `request_refund_callback` to block refunds on already-deposited UTXOs. Because both code paths share one set with no distinction between "processed as unavailable" and "processed as a real deposit", any below-minimum deposit that a relayer processes is permanently unrefundable on-chain.

### Finding Description

**Step 1 — Entry point (public):** A user sends BTC below `config.min_deposit_amount` to a valid bridge deposit address. This is a public Bitcoin action; no contract permission is required.

**Step 2 — Relayer processes it (expected behavior):** A whitelisted relayer calls `verify_deposit` / `verify_deposit_v2`. Both are gated by `#[trusted_relayer]`, but processing every confirmed deposit to a bridge address is the relayer's normal duty. [1](#0-0) 

**Step 3 — Below-min branch:** `internal_verify_deposit` detects `deposit_amount < config.min_deposit_amount` and chains to `unavailable_utxo_callback` instead of the normal mint callback. [2](#0-1) 

**Step 4 — `verified_deposit_utxo` poisoned:** `unavailable_utxo_callback` unconditionally inserts the UTXO key into `verified_deposit_utxo` and then into `unavailable_utxos`. [3](#0-2) 

**Step 5 — `request_refund` permanently blocked:** `request_refund` is publicly callable (no `#[trusted_relayer]` at the method level). Its callback hard-rejects any UTXO already present in `verified_deposit_utxo`: [4](#0-3) 

`execute_refund` has the same guard: [5](#0-4) 

**Step 6 — No on-chain recovery path:** `unavailable_utxos` is a read-only view map. There is no contract function that removes a UTXO from `verified_deposit_utxo` or routes an `unavailable_utxo` through the refund pipeline. The only view functions are `get_unavailable_utxos_paged` / `list_unavailable_utxos`. [6](#0-5) 

### Impact Explanation

Any user who sends BTC below `min_deposit_amount` to a valid deposit address has their funds permanently locked once a relayer processes the transaction. The BTC sits in `unavailable_utxos` on-chain with no callable function to recover it. Recovery requires a DAO-governed contract upgrade. This matches the allowed Critical impact: **permanent locking of user funds**.

### Likelihood Explanation

Below-minimum deposits are a realistic accident (dust, fee miscalculation, test sends). Relayers are expected to submit proofs for all confirmed deposits to bridge addresses — the contract itself accepts and routes them without rejecting at the entry point. The collision is deterministic once a relayer processes the transaction.

### Recommendation

Separate the two uses of `verified_deposit_utxo`. Options:

1. **Dedicated set:** Add a `verified_unavailable_utxo: LookupSet<String>` for below-min replay protection, leaving `verified_deposit_utxo` exclusively for finalized deposits. `request_refund_callback` and `load_refund_request_for_execute` only check `verified_deposit_utxo`, so below-min UTXOs would remain refundable.

2. **Allow refund path for unavailable UTXOs:** In `request_refund_callback`, additionally check whether the UTXO is in `unavailable_utxos`; if so, permit the refund request despite the `verified_deposit_utxo` membership.

3. **Add an operator recovery function:** Expose a DAO/Operator-gated `recover_unavailable_utxo` that removes the key from `verified_deposit_utxo` and `unavailable_utxos` and creates a refund request.

### Proof of Concept

```
1. User sends 500 sats (below min_deposit_amount) to a valid bridge deposit address.
2. Relayer calls verify_deposit_v2(deposit_msg, tx_bytes, vout=0, proof).
   → internal_verify_deposit: deposit_amount(500) < min_deposit_amount → unavailable_utxo_callback
   → verified_deposit_utxo.insert("txid@0")  // ← poisons the set
   → unavailable_utxos.insert("txid@0", utxo)
   → Event::UnavailableUtxo emitted
3. User calls request_refund(deposit_msg, refund_address, tx_bytes, vout=0, proof, None)
   → request_refund_callback:
       verified_deposit_utxo.contains("txid@0") == true
       → PANIC: "UTXO already verified via deposit"
4. User's 500 sats are permanently locked. No further on-chain call can recover them.
``` [7](#0-6) [8](#0-7)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L26-47)
```rust
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    #[deprecated(note = "use verify_deposit_v2")]
    pub fn verify_deposit(
        &mut self,
        deposit_msg: DepositMsg,
        tx_bytes: Vec<u8>,
        vout: usize,
        tx_block_blockhash: String,
        tx_index: u64,
        merkle_proof: Vec<String>,
    ) -> Promise {
        self.internal_verify_deposit_entry(
            deposit_msg,
            tx_bytes,
            vout,
            tx_block_blockhash,
            tx_index,
            merkle_proof,
            None,
        )
    }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L45-50)
```rust
        if deposit_amount < config.min_deposit_amount {
            promise.then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_UNAVAILABLE_UTXO_CALL_BACK)
                    .unavailable_utxo_callback(recipient_id, pending_utxo_info),
            )
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L296-323)
```rust
    pub fn unavailable_utxo_callback(
        &mut self,
        recipient_id: AccountId,
        pending_utxo_info: PendingUTXOInfo,
    ) -> PromiseOrValue<bool> {
        let result_bytes = env::promise_result_checked(0, MAX_BOOL_RESULT)
            .expect("Call verify_transaction_inclusion failed");
        let is_valid = serde_json::from_slice::<bool>(&result_bytes)
            .expect("verify_transaction_inclusion return not bool");
        require!(is_valid, "verify_transaction_inclusion return false");
        require!(
            self.data_mut()
                .verified_deposit_utxo
                .insert(pending_utxo_info.utxo_storage_key.clone()),
            "Already deposit utxo"
        );
        let deposit_amount = u128::from(pending_utxo_info.utxo.balance);
        self.internal_set_unavailable_utxo(
            &pending_utxo_info.utxo_storage_key,
            pending_utxo_info.utxo,
        );
        Event::UnavailableUtxo {
            recipient_id: &recipient_id,
            utxo_storage_key: &pending_utxo_info.utxo_storage_key,
            amount: deposit_amount.into(),
        }
        .emit();
        PromiseOrValue::Value(true)
```

**File:** contracts/satoshi-bridge/src/refund.rs (L254-258)
```rust
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L496-541)
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
```

**File:** contracts/satoshi-bridge/src/api/view.rs (L178-209)
```rust
    pub fn get_unavailable_utxos_paged(
        &self,
        from_index: Option<usize>,
        limit: Option<usize>,
    ) -> HashMap<String, UTXO> {
        let len = usize::try_from(self.data().unavailable_utxos.len())
            .unwrap_or_else(|_| env::panic_str("Too many unavailable_utxos"));
        let skip_n = from_index.unwrap_or(0);
        let take_n = limit.unwrap_or(len - skip_n);
        self.data()
            .unavailable_utxos
            .iter()
            .skip(skip_n)
            .take(take_n)
            .map(|(k, v)| (k.clone(), v.into()))
            .collect()
    }

    pub fn list_unavailable_utxos(
        &self,
        utxo_storage_keys: Vec<String>,
    ) -> HashMap<String, Option<UTXO>> {
        utxo_storage_keys
            .into_iter()
            .map(|key| {
                (
                    key.clone(),
                    self.data().unavailable_utxos.get(&key).map(Into::into),
                )
            })
            .collect()
    }
```
