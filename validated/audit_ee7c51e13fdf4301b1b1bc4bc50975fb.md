### Title
`safe_mint` Panic Causes Permanent UTXO Lock With No nBTC Minted — (`contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

### Summary

When `safe_mint` panics on the nBTC contract, `is_refund_required()` returns `false` (the `Err(_)` arm), causing `safe_mint_callback` to set `is_success = true` and call `internal_set_utxo`. Because `verified_deposit_utxo` was already populated in `verify_safe_deposit_callback` before the `safe_mint` call, the UTXO ends up permanently recorded in both maps with zero nBTC ever minted. No recovery path exists.

### Finding Description

**Step 1 — `verify_safe_deposit_callback` inserts the UTXO key before calling `safe_mint`:**

`verified_deposit_utxo.insert(...)` is called unconditionally at lines 399–403, then `safe_mint` is dispatched as a chained promise. [1](#0-0) 

**Step 2 — `is_refund_required()` maps a panic (`Err(_)`) to `false`:**

The `Err(_)` arm at line 487 returns `false`, meaning "no refund needed." The comment at lines 471–473 explicitly documents this as intentional ("for safety, to avoid a potential double spend"), but the reasoning is incorrect for NEAR's execution model: a panicking cross-contract call always rolls back its own state changes, so no tokens can have been minted. [2](#0-1) 

**Step 3 — `safe_mint_callback` treats the panic as success and stores the UTXO:**

`is_success = !is_refund_required()` evaluates to `true`, so `internal_set_utxo` is called and the UTXO is permanently written to the `utxos` map. [3](#0-2) 

**Step 4 — No recovery path:**

- `verified_deposit_utxo` contains the key → any re-deposit attempt hits the `"Already deposit utxo"` guard at line 402.
- The UTXO is in `utxos` (spendable by the bridge for withdrawals) but the depositor holds zero nBTC and cannot initiate a withdrawal.
- The UTXO is not placed in `unavailable_utxos`, so no operator-side recovery flow is triggered. [4](#0-3) 

### Impact Explanation

The depositor's BTC is permanently locked inside the bridge's UTXO set with no corresponding nBTC ever issued. The invariant "a UTXO is stored only if the mint succeeded" is broken. This is a stuck-bridge-state / broken-callback-rollback scenario matching the **Low** (and arguably **Medium**) allowed impact scope.

### Likelihood Explanation

`safe_mint` can panic under several realistic conditions reachable without any privileged role:

1. **Unregistered recipient** — the depositor supplies a `recipient_id` that has not registered storage in the nBTC contract; NEP-141 storage-management panics are common.
2. **Gas shortfall** — `GAS_FOR_MINT_CALL` is a static allocation; if the nBTC contract's `safe_mint` path (including any `ft_transfer_call` leg) consumes more gas than allocated, it panics.
3. **nBTC contract storage exhaustion** — a full storage trie causes any state-writing call to panic.

All three are reachable from a public `safe_verify_deposit` call with no operator involvement. [5](#0-4) 

### Recommendation

Replace the `Err(_) => false` arm in `is_refund_required()` with `Err(_) => true`. A panic from `safe_mint` guarantees (by NEAR's execution model) that no tokens were minted, so the correct response is to refund the depositor and remove the UTXO key from `verified_deposit_utxo`, exactly as the `is_success = false` branch already does. [6](#0-5) 

### Proof of Concept

```
1. Deploy bridge + nBTC contracts on sandbox.
2. Call safe_verify_deposit with a valid BTC proof and a recipient_id
   that is NOT registered for storage in the nBTC contract.
3. Light-client callback succeeds → verify_safe_deposit_callback runs:
     verified_deposit_utxo.insert(key)  ← key is now present
     safe_mint dispatched               ← will panic (unregistered account)
4. safe_mint panics → NEAR rolls back nBTC state (0 tokens minted).
5. safe_mint_callback fires:
     promise_result_checked(0, …) → Err(_)
     is_refund_required() → false
     is_success = true
     internal_set_utxo(key, utxo)  ← UTXO stored
6. Assert: verified_deposit_utxo.contains(key) == true
           utxos.contains(key)              == true
           nbtc.ft_total_supply()           == unchanged (0 minted)
7. Attempt re-deposit with same UTXO → panics "Already deposit utxo".
   Depositor's BTC is permanently locked with no nBTC.
```

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L399-418)
```rust
        require!(
            self.data_mut()
                .verified_deposit_utxo
                .insert(pending_utxo_info.utxo_storage_key.clone()),
            "Already deposit utxo"
        );

        let msg = (!msg.is_empty())
            .then(|| inject_utxo_id_in_msg(msg, &pending_utxo_info.utxo_storage_key));

        ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
            .with_static_gas(GAS_FOR_MINT_CALL)
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .safe_mint(recipient_id.clone(), mint_amount, msg)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_MINT_CALL_BACK)
                    .safe_mint_callback(recipient_id.clone(), mint_amount, pending_utxo_info),
            )
            .into()
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L428-437)
```rust
        let is_success = !is_refund_required();
        let relayer_account_id = env::signer_account_id();

        if is_success {
            Event::UtxoAdded {
                utxo_storage_keys: vec![pending_utxo_info.utxo_storage_key.clone()],
                balances: Some(vec![U128(pending_utxo_info.utxo.balance.into())]),
            }
            .emit();
            self.internal_set_utxo(&pending_utxo_info.utxo_storage_key, pending_utxo_info.utxo);
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L474-489)
```rust
fn is_refund_required() -> bool {
    match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
        Ok(value) => {
            if let Ok(amount) = near_sdk::serde_json::from_slice::<U128>(&value) {
                // Normal case: refund if the used token amount is zero
                // The amount can be zero if the `ft_on_transfer` in the receiver contract returns an amount instead of `0`, or if it panics.
                amount.0 == 0
            } else {
                // Unexpected case: don't refund
                false
            }
        }
        // Unexpected case: don't refund
        Err(_) => false,
    }
}
```
