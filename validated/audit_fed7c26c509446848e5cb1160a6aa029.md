I have all the code I need to make a determination. Let me trace the full path.

**Code path traced:**

1. `internal_verify_deposit_entry` reads `deposit_amount` from tx bytes, then calls `internal_verify_deposit`. [1](#0-0) 

2. When `deposit_amount < config.min_deposit_amount`, the callback routed is `unavailable_utxo_callback`. [1](#0-0) 

3. `unavailable_utxo_callback` inserts the UTXO key into `verified_deposit_utxo` AND into `unavailable_utxos`. No nBTC is minted. No refund request is created. [2](#0-1) 

4. `internal_set_unavailable_utxo` only inserts — there is no corresponding remove anywhere in production code (grep for `unavailable_utxos.*remove` returns zero matches). [3](#0-2) 

5. `load_refund_request_for_execute` blocks `execute_refund` if the UTXO is in `verified_deposit_utxo` (unless `refund_request.executed == true`, which requires a prior `request_refund` call). [4](#0-3) 

6. `request_refund_callback` also checks `verified_deposit_utxo` and panics with "UTXO already verified via deposit" — confirmed by the test `test_refund_double_request_after_execute`. [5](#0-4) 

**Key finding**: Once `unavailable_utxo_callback` runs, the UTXO is in `verified_deposit_utxo`. Any subsequent `request_refund` call for that UTXO will be rejected. There is no operator-level function to remove entries from `unavailable_utxos` or to create a refund request for them. The BTC is permanently locked.

**However**, there is one escape hatch: if the user calls `request_refund` *before* the relayer calls `verify_deposit`, a `RefundRequest` is stored. Then when `verify_deposit` runs and inserts into `verified_deposit_utxo`, `execute_refund` still works because `refund_request.executed` is checked. But this race window is narrow and not guaranteed.

**On the "unprivileged attacker" framing**: `verify_deposit` is callable by any account (non-whitelisted callers just require more confirmations). So an attacker can directly call `verify_deposit` with a below-minimum deposit without relayer cooperation.

---

### Title
Below-minimum deposit permanently locks user BTC with no recovery path — (`contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

### Summary
When `verify_deposit` is called for a BTC amount below `min_deposit_amount`, `unavailable_utxo_callback` inserts the UTXO into both `verified_deposit_utxo` and `unavailable_utxos` without minting nBTC and without creating a refund request. Because `verified_deposit_utxo` membership blocks all subsequent `request_refund` calls, and no operator function exists to remove entries from `unavailable_utxos`, the deposited BTC is permanently locked with no recovery mechanism.

### Finding Description
`internal_verify_deposit` branches on `deposit_amount < config.min_deposit_amount`: [1](#0-0) 

The callback `unavailable_utxo_callback` then:
- Inserts `utxo_storage_key` into `verified_deposit_utxo` (replay guard)
- Inserts the UTXO into `unavailable_utxos` via `internal_set_unavailable_utxo`
- Emits `UnavailableUtxo` event
- Returns `true` — no mint, no refund request [2](#0-1) 

`internal_set_unavailable_utxo` is a write-only operation with no corresponding delete anywhere in the production codebase: [3](#0-2) 

After this, `request_refund_callback` and `execute_refund` both check `verified_deposit_utxo` and reject the UTXO: [4](#0-3) 

### Impact Explanation
The deposited BTC is permanently locked:
- No nBTC is minted to the user
- No refund request is created
- `verified_deposit_utxo` membership blocks all future `request_refund` calls for this UTXO
- `unavailable_utxos` has no removal path in production code
- The UTXO cannot be used in withdrawals (only `utxos`, not `unavailable_utxos`, feeds the withdrawal system)

This constitutes permanent loss of user BTC funds.

### Likelihood Explanation
Any account can call `verify_deposit` (non-whitelisted callers pay extra confirmations but are not blocked). A user who accidentally sends dust, or an attacker who deliberately sends below-minimum BTC to a deposit address, triggers this path. The relayer also naturally processes all confirmed BTC transactions to deposit addresses, including below-minimum ones. The scenario is reachable in normal operation.

### Recommendation
One of:
1. Do not insert below-minimum UTXOs into `verified_deposit_utxo` in `unavailable_utxo_callback`, so the refund path remains open.
2. Automatically create a `RefundRequest` inside `unavailable_utxo_callback` when a `refund_address` is present in the `DepositMsg`.
3. Add an operator/DAO function to remove entries from `unavailable_utxos` and `verified_deposit_utxo` to enable manual recovery.

### Proof of Concept
```
1. User sends 1000 sat (below min_deposit_amount = 20000) to a deposit address derived from DepositMsg{recipient_id: alice, refund_address: None}
2. Any account calls verify_deposit(deposit_msg, tx_bytes, vout=0, proof)
3. internal_verify_deposit routes to unavailable_utxo_callback (deposit_amount < min_deposit_amount)
4. unavailable_utxo_callback:
   - verified_deposit_utxo.insert(utxo_key) → true (first insert)
   - unavailable_utxos.insert(utxo_key, utxo)
   - emits UnavailableUtxo event
5. User calls request_refund(deposit_msg, tx_bytes, ...) → panics "UTXO already verified via deposit"
6. No nBTC minted. No refund path. BTC permanently locked.
```

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L45-50)
```rust
        if deposit_amount < config.min_deposit_amount {
            promise.then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_UNAVAILABLE_UTXO_CALL_BACK)
                    .unavailable_utxo_callback(recipient_id, pending_utxo_info),
            )
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L296-324)
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
    }
```

**File:** contracts/satoshi-bridge/src/utxo.rs (L87-91)
```rust
    pub fn internal_set_unavailable_utxo(&mut self, utxo_storage_key: &str, utxo: UTXO) {
        self.data_mut()
            .unavailable_utxos
            .insert(utxo_storage_key.to_owned(), utxo.into());
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L254-258)
```rust
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );
```

**File:** contracts/satoshi-bridge/tests/test_refund.rs (L789-803)
```rust
    // 3. Second request_refund — should fail (UTXO marked in verified_deposit_utxo)
    check!(
        context.request_refund(
            "alice",
            deposit_msg,
            TARGET_ADDRESS,
            tx_bytes,
            vout,
            blockhash,
            1,
            vec![],
            None
        ),
        "UTXO already verified via deposit"
    );
```
