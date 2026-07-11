### Title
Non-Atomic Pre-Call Guard Enables Duplicate MPC Sign Dispatch, Causing Panic and NEAR Deposit Loss in Second Callback — (`contracts/satoshi-bridge/src/chain_signature.rs`)

---

### Summary

`internal_sign_btc_transaction` performs a read-only guard check (`signatures[sign_index].is_none()`) but writes nothing to contract state before dispatching the MPC sign promise. Two concurrent public calls for the same `btc_pending_sign_id` and `sign_index` can both pass this guard, both forward their attached NEAR deposit to the MPC contract, and both schedule `sign_btc_transaction_callback`. The first callback succeeds; the second panics inside the `Ok` branch, reverting its state changes while the NEAR deposit it forwarded to MPC is already consumed and unrecoverable.

---

### Finding Description

`sign_btc_transaction` is a public, payable, unpermissioned function (the `#[pause(except(roles(Role::DAO)))]` macro only allows DAO to pause it; it imposes no caller restriction): [1](#0-0) 

Inside `internal_sign_btc_transaction`, the only pre-dispatch guard is a read of the current state: [2](#0-1) 

No write to `signatures[sign_index]` occurs before the promise is dispatched. The full deposit is forwarded to the MPC contract immediately: [3](#0-2) 

Because NEAR cross-contract calls are asynchronous, a second transaction submitted before either callback lands sees the same unmodified state and passes the same guard. Both calls schedule `sign_btc_transaction_callback`: [4](#0-3) 

When the second callback executes, `signatures[sign_index]` is already `Some(...)` (written by the first callback), so the callback-level guard panics: [5](#0-4) 

The panic reverts all state changes in the second callback, but the NEAR deposit that was already forwarded to the MPC contract in the second call is not returned.

---

### Impact Explanation

- The second caller's attached NEAR deposit (MPC signing fee) is permanently lost.
- If the first callback had already transitioned the `BTCPendingInfo` to `PendingVerify` (all inputs signed), the second callback's panic leaves the bridge state consistent from the first callback's perspective, but the second caller has no recourse for their lost deposit.
- No bridge funds are stolen and no permanent stuck state results, placing this squarely in the **Low** impact tier: publicly reachable panic-driven fault in a production bridge path without direct theft.

---

### Likelihood Explanation

Any unprivileged account can call `sign_btc_transaction`. The window for the race is the full MPC signing latency (typically several seconds on NEAR), which is wide enough to be triggered accidentally by a retry or deliberately by a griefing attacker. No special knowledge beyond the public `btc_pending_sign_id` (observable on-chain) is required.

---

### Recommendation

Reserve the slot atomically before dispatching the MPC promise. Set `signatures[sign_index]` to a sentinel value (e.g., a placeholder `Some(...)`) in `internal_sign_btc_transaction` immediately after the guard check, before the promise is dispatched. The callback then replaces the sentinel with the real signature. This makes the guard and the reservation a single atomic state transition, closing the race window entirely.

---

### Proof of Concept

```
1. Observe a BTCPendingInfo with btc_pending_sign_id = X in PendingSign stage,
   signatures[0] = None.

2. Submit TX-A: sign_btc_transaction(X, 0, kv) with deposit D_A.
   → internal_sign_btc_transaction reads signatures[0] == None ✓
   → Forwards D_A to MPC; schedules callback_A.
   → State unchanged: signatures[0] still None.

3. Before callback_A lands, submit TX-B: sign_btc_transaction(X, 0, kv) with deposit D_B.
   → internal_sign_btc_transaction reads signatures[0] == None ✓ (still unwritten)
   → Forwards D_B to MPC; schedules callback_B.

4. callback_A fires:
   → signatures[0].is_none() == true ✓
   → Writes signatures[0] = Some(sig_A).
   → If all signed: transitions to PendingVerify, removes from btc_pending_sign_ids.

5. callback_B fires:
   → signatures[0].is_none() == false → require! panics → "Already signed"
   → All state changes in callback_B are reverted.
   → D_B (already consumed by MPC) is permanently lost.
```

### Citations

**File:** contracts/satoshi-bridge/src/api/chain_signatures.rs (L19-26)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_btc_transaction(
        &mut self,
        btc_pending_sign_id: String,
        sign_index: usize,
        key_version: u32,
    ) -> PromiseOrValue<bool> {
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L62-68)
```rust
    pub fn sign_promise(&self, request: SignRequest) -> Promise {
        let config = self.internal_config();
        ext_chain_signatures::ext(config.chain_signatures_account_id.clone())
            .with_static_gas(GAS_FOR_SIGN_CALL)
            .with_attached_deposit(env::attached_deposit())
            .sign(request)
    }
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L90-94)
```rust
        let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);
        require!(
            btc_pending_info.signatures[sign_index].is_none(),
            "Already signed"
        );
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L104-112)
```rust
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_FOR_SIGN_BTC_TRANSACTION_CALL_BACK)
                .sign_btc_transaction_callback(
                    btc_pending_info.account_id.clone(),
                    btc_pending_sign_id,
                    sign_index,
                ),
        )
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L154-157)
```rust
            require!(
                btc_pending_info.signatures[sign_index].is_none(),
                "Already signed"
            );
```
