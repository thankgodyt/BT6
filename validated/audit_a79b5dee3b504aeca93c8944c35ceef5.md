### Title
Concurrent `request_refund` Calls for the Same UTXO Cause Permanent Loss of Second Caller's 2 NEAR Storage Deposit — (`contracts/satoshi-bridge/src/refund.rs`)

---

### Summary

`request_refund` is publicly callable (no individual `#[trusted_relayer]` gate). Two concurrent calls for the same UTXO both pass light-client verification, but the second `request_refund_callback` panics on the duplicate-key check. Because the 2 NEAR deposit was already transferred to the contract when the original call executed, the panic does not roll it back — the deposit is permanently lost.

---

### Finding Description

**Entrypoint — `request_refund` is public.**

`request_refund` sits inside a `#[trusted_relayer]` impl block, but that attribute on the block only generates whitelist-management helpers; it does not gate individual functions. The function carries only `#[payable]` and `#[pause]` — no individual `#[trusted_relayer]`. Compare: `verify_refund_finalize` and `remove_refund_pending_tx_id` in the same block each carry their own `#[trusted_relayer]`, while `request_refund`, `reject_refund`, and `execute_refund` do not. [1](#0-0) 

**Deposit is taken immediately and declared non-refundable.**

`internal_request_refund` requires `env::attached_deposit() >= required_balance_for_request_refund()` and then fires the XCC. The deposit is transferred to the contract at that point. The doc-comment explicitly states: *"The deposit is NOT refunded — it covers request storage and acts as an anti-spam fee."* [2](#0-1) 

**The callback panics on a duplicate key — no refund path.**

`request_refund_callback` (a `#[private]` callback) re-checks for the duplicate after the XCC resolves. If another call's callback already inserted the same `utxo_storage_key`, this one panics. The comment even acknowledges the race: *"Double-check no duplicate (another request_refund could have landed between our check and callback)"*. The panic reverts the callback's state changes but cannot undo the deposit transfer from the earlier receipt. [3](#0-2) 

**Concrete race sequence:**

```
Block N:   Caller A → request_refund(UTXO X) + 2 NEAR attached → XCC scheduled
Block N:   Caller B → request_refund(UTXO X) + 2 NEAR attached → XCC scheduled

Block N+k: XCC-A resolves → request_refund_callback_A:
             !refund_requests.contains_key("X") == true → inserts request → OK

Block N+k: XCC-B resolves → request_refund_callback_B:
             !refund_requests.contains_key("X") == false → PANIC
             → B's 2 NEAR is NOT returned
```

Both XCCs succeed because the UTXO genuinely exists on-chain. The ordering of callbacks is non-deterministic and depends on receipt scheduling.

---

### Impact Explanation

The second caller permanently loses their 2 NEAR storage deposit even though their call was valid at submission time. There is no recovery path: the contract has no mechanism to credit or refund a deposit whose callback panicked, and the non-refundability is hard-coded by design. This is a broken-callback-rollback pattern — the deposit transfer is not atomic with the callback's success. [4](#0-3) 

---

### Likelihood Explanation

The scenario arises naturally (two users independently discover the same stuck UTXO) and can be deliberately triggered by a griefing attacker who front-runs a victim's `request_refund` with their own call for the same UTXO. The attacker spends 2 NEAR to cause the victim to lose 2 NEAR. NEAR's asynchronous receipt model makes the ordering of callbacks non-deterministic, so even a single user retrying after a failed attempt could hit this if a concurrent call is in flight.

---

### Recommendation

In `request_refund_callback`, replace the `require!` panic on a duplicate key with a graceful return that refunds the attached deposit to the original caller via `Promise::new(predecessor).transfer(attached_deposit)`. The `#[private]` callback has access to `env::predecessor_account_id()` (the contract itself) but the original caller must be passed as a parameter (as is already done for other values like `deposit_msg`). Alternatively, pass the original caller's account ID into the callback and issue a refund transfer instead of panicking. [5](#0-4) 

---

### Proof of Concept

```rust
// Pseudocode — both calls attach required_balance_for_request_refund() (≈2 NEAR)
let utxo = same_btc_utxo();

// Caller A submits first
contract.request_refund(deposit_msg.clone(), addr_a, tx_bytes.clone(), vout, proof.clone(), None);

// Caller B submits concurrently (before A's callback resolves)
contract.request_refund(deposit_msg.clone(), addr_b, tx_bytes.clone(), vout, proof.clone(), None);

// Both XCCs succeed (UTXO is on-chain)
// A's callback lands first → inserts refund_requests["txid@vout"]
// B's callback lands second → panics "Refund request already exists for this UTXO"
// B's 2 NEAR is permanently retained by the contract
assert!(contract.get_refund_request("txid@vout").is_some()); // A's request exists
assert_eq!(near_balance_of(caller_b), initial_balance - 2_NEAR); // B's deposit gone
```

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L480-510)
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
```

**File:** contracts/satoshi-bridge/src/refund.rs (L146-149)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_request_refund(),
            "Insufficient deposit for storage"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L496-548)
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
