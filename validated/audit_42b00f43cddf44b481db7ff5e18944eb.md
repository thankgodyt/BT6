### Title
Attached NEAR Deposit Permanently Stuck on `request_refund_callback` Failure - (File: `contracts/satoshi-bridge/src/refund.rs`)

### Summary
`request_refund` is a `#[payable]` function requiring a 2 NEAR attached deposit. When the asynchronous `request_refund_callback` fails (light client returns false, UTXO already verified, or duplicate request), the callback's state changes are rolled back but the 2 NEAR deposit is permanently retained by the contract with no recovery path for the caller.

### Finding Description
`request_refund` enforces a minimum attached deposit of 2 NEAR before initiating a cross-contract call to the BTC light client: [1](#0-0) 

It then chains `request_refund_callback` as a continuation: [2](#0-1) 

Inside `request_refund_callback`, multiple `require!` guards can panic and roll back the callback's state changes: [3](#0-2) [4](#0-3) [5](#0-4) 

In NEAR's execution model, the original call (which transferred the 2 NEAR deposit to the contract) is a separate receipt from the callback. When the callback receipt panics, only the callback's state mutations are rolled back — the deposit transfer from the original call is **not** reversed. The 2 NEAR remains in the contract balance permanently.

The `required_balance_for_request_refund` view function explicitly documents this as intentional for the success path ("The deposit is NOT refunded — it covers request storage and acts as an anti-spam fee"): [6](#0-5) 

However, in the failure path no storage is consumed (the `refund_requests` insert is rolled back), so the deposit neither covers storage nor serves a meaningful anti-spam purpose — it is simply lost. There is no admin or user-facing function to recover stuck NEAR; `claim_lost_found` only handles nBTC balances: [7](#0-6) 

The same pattern applies to `execute_refund`, which requires 1 NEAR and can panic inside `load_refund_request_for_execute` (timelock not elapsed, UTXO already verified) after the deposit is already transferred: [8](#0-7) [9](#0-8) 

### Impact Explanation
Every failed `request_refund` call causes a permanent loss of 2 NEAR for the caller, and every failed `execute_refund` call causes a permanent loss of 1 NEAR. No recovery mechanism exists for either case. This constitutes harmful smart-contract behavior matching the "broken callback rollback" Medium impact class: user funds are permanently locked in the contract without any theft or privileged action required.

### Likelihood Explanation
`request_refund` is a permissionless, publicly callable entrypoint. Failure is reachable via:
- Submitting an invalid or stale Merkle proof (light client returns `false`)
- Calling after the UTXO was already finalized via `verify_deposit`
- A race condition where two callers submit `request_refund` for the same UTXO concurrently (the second callback hits the duplicate-request guard)

All three paths are realistic for ordinary bridge users, not just adversaries.

### Recommendation
Refund the attached deposit to `env::predecessor_account_id()` (captured before the async call) inside `request_refund_callback` when any `require!` guard fails, using `Promise::new(caller).transfer(env::attached_deposit())`. The same pattern should be applied in `execute_refund` / `internal_execute_refund` on failure. Alternatively, reduce the required deposit to a nominal yoctoNEAR anti-spam fee and handle actual storage costs internally.

### Proof of Concept
1. Alice calls `request_refund` attaching exactly 2 NEAR with a syntactically valid but stale Merkle proof (block already pruned from the light client).
2. The contract accepts the deposit and dispatches the light-client cross-contract call.
3. The light client returns `false`; `request_refund_callback` hits `require!(is_valid, "verify_transaction_inclusion return false")` and panics.
4. The callback receipt is rolled back — no `RefundRequest` is stored, no storage is consumed.
5. The original receipt (which transferred 2 NEAR) is **not** rolled back; the 2 NEAR remains in the contract.
6. Alice has no function to call to recover her 2 NEAR; `claim_lost_found` only covers nBTC.

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L146-149)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_request_refund(),
            "Insufficient deposit for storage"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L179-183)
```rust
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_FOR_REQUEST_REFUND_CALLBACK)
                .request_refund_callback(deposit_msg, refund_address, tx_bytes, vout, gas_fee),
        )
```

**File:** contracts/satoshi-bridge/src/refund.rs (L201-205)
```rust
    pub(crate) fn resolve_execute_refund_timelock(&self, utxo_storage_key: &str) -> u64 {
        require!(
            env::attached_deposit() >= self.required_balance_for_execute_refund(),
            "Insufficient deposit for storage"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L505-509)
```rust
        let result_bytes = env::promise_result_checked(0, MAX_BOOL_RESULT)
            .expect("Call verify_transaction_inclusion failed");
        let is_valid = serde_json::from_slice::<bool>(&result_bytes)
            .expect("verify_transaction_inclusion return not bool");
        require!(is_valid, "verify_transaction_inclusion return false");
```

**File:** contracts/satoshi-bridge/src/refund.rs (L534-541)
```rust
        // Double-check not finalized (could have been verified between request and callback)
        require!(
            !self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key),
            "UTXO already verified via deposit"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L543-547)
```rust
        // Double-check no duplicate (another request_refund could have landed between our check and callback)
        require!(
            !self.data().refund_requests.contains_key(&utxo_storage_key),
            "Refund request already exists for this UTXO"
        );
```

**File:** contracts/satoshi-bridge/src/api/view.rs (L322-328)
```rust
    pub fn required_balance_for_execute_refund(&self) -> NearToken {
        // Measured real storage: ~0.012 NEAR (Bitcoin) up to ~0.134 NEAR (Zcash shielded,
        // whose pending info embeds the Orchard bundle). The deposit is NOT refunded, so
        // 1 NEAR covers the heaviest case and acts as an anti-spam fee on this
        // permissionless entrypoint — refunds are a rare, abnormal event anyway.
        NearToken::from_near(1)
    }
```

**File:** contracts/satoshi-bridge/src/api/view.rs (L330-339)
```rust
    pub fn required_balance_for_request_refund(&self) -> NearToken {
        // request_refund stores a RefundRequest holding the deposit tx_bytes verbatim, so
        // storage grows ~1:1 with tx size (measured: storage ≈ tx_bytes + ~442 bytes). A
        // normal deposit (1-2 inputs, ~500 bytes) costs ~0.005 NEAR, but tx_bytes is capped
        // at MAX_REQUEST_REFUND_TX_BYTES (200 KB) — at that worst case storage is ~2 NEAR.
        // We size the deposit to cover that worst case; for normal deposits the bulk of it
        // is an anti-spam fee on this permissionless entrypoint (the deposit is NOT refunded).
        // Refunds are a rare, abnormal event anyway.
        NearToken::from_near(2)
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L449-460)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn claim_lost_found(&mut self) -> Promise {
        assert_one_yocto();
        let account_id = env::predecessor_account_id();
        let amount = self
            .data_mut()
            .lost_found
            .remove(&account_id)
            .expect("The account does not have lostfound");
        self.internal_transfer_nbtc(&account_id, amount)
    }
```
