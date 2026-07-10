### Title
Premature `verified_deposit_utxo` Commit Before `safe_mint` Completes Permanently Locks User BTC If Callback Panics — (`contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

---

### Summary

In `verify_safe_deposit_callback`, the bridge irrevocably inserts the UTXO key into `verified_deposit_utxo` **before** the `safe_mint` cross-contract call completes. A rollback is attempted in `safe_mint_callback`, but if `safe_mint_callback` itself panics (e.g., OOG), NEAR reverts only that callback's state changes — the prior insertion is already committed. The UTXO is then permanently locked: no nBTC is minted and no refund is possible.

---

### Finding Description

`verify_safe_deposit_callback` runs as a NEAR callback after the BTC Light Client confirms the deposit. Inside it, two things happen in sequence:

1. `verified_deposit_utxo.insert(utxo_storage_key)` is executed and **committed** as part of this callback transaction.
2. A new cross-contract call chain is scheduled: `safe_mint` → `safe_mint_callback`. [1](#0-0) 

`safe_mint_callback` is the only place that rolls back the `verified_deposit_utxo` entry on failure: [2](#0-1) 

Because each NEAR callback is a **separate transaction**, if `safe_mint_callback` panics (OOG, storage error, or any unexpected panic), NEAR reverts all state mutations inside that callback — but the `verified_deposit_utxo.insert(...)` from the previous transaction is already durably committed. The rollback never executes.

The refund path explicitly blocks refunds for UTXOs already in `verified_deposit_utxo` (unless `refund_request.executed` is true, which it is not in this scenario): [3](#0-2) 

There is no recovery path: the UTXO cannot be deposited (already in `verified_deposit_utxo`) and cannot be refunded (blocked by the same set).

Additionally, if `safe_mint` itself panics (e.g., OOG due to insufficient `GAS_FOR_MINT_CALL`), `is_refund_required()` returns `false` via the `Err(_) => false` branch, causing `is_success = true`. The UTXO is then added to the bridge's available pool as if the mint succeeded, but no nBTC was ever issued to the user: [4](#0-3) [5](#0-4) 

---

### Impact Explanation

**Primary scenario** (`safe_mint_callback` panics): User's BTC deposit is permanently locked — no nBTC minted, no refund possible. The UTXO is consumed from the user's perspective but never enters the bridge's available pool. Funds are stuck indefinitely, requiring operator intervention to resolve (if resolution is even possible without a contract upgrade).

**Secondary scenario** (`safe_mint` panics, `safe_mint_callback` treats it as success): The UTXO enters the bridge's available pool with no corresponding nBTC backing. The bridge can later spend this UTXO for another user's withdrawal, effectively using the victim's BTC to service a different user's withdrawal — a permanent loss for the depositor.

Both scenarios match: **Medium — broken callback rollback / stuck bridge state requiring operator intervention**, and the secondary scenario approaches **Critical — significant loss of user funds**.

---

### Likelihood Explanation

The `safe_verify_deposit` entrypoint is publicly callable by any NEAR account submitting a valid BTC Merkle proof. The gas constants `GAS_FOR_MINT_CALL` and `GAS_FOR_MINT_CALL_BACK` are fixed at compile time. If the nbtc contract's `safe_mint` or any logic in `safe_mint_callback` (e.g., `internal_set_utxo`, storage writes) consumes more gas than allocated — due to contract upgrades, storage growth, or misconfiguration — the callback panics and the UTXO is permanently locked. This is a latent risk that grows over time as the contract state grows.

---

### Recommendation

**Short term:** In `safe_mint_callback`, check whether the callback itself is executing successfully before relying on the rollback path. Consider using a two-phase commit: do not insert into `verified_deposit_utxo` in `verify_safe_deposit_callback`; instead, insert it only inside `safe_mint_callback` after confirming `safe_mint` succeeded. This mirrors the NEAR

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L398-418)
```rust
        require!(is_valid, "verify_transaction_inclusion return false");
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

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L431-437)
```rust
        if is_success {
            Event::UtxoAdded {
                utxo_storage_keys: vec![pending_utxo_info.utxo_storage_key.clone()],
                balances: Some(vec![U128(pending_utxo_info.utxo.balance.into())]),
            }
            .emit();
            self.internal_set_utxo(&pending_utxo_info.utxo_storage_key, pending_utxo_info.utxo);
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L438-441)
```rust
        } else {
            self.data_mut()
                .verified_deposit_utxo
                .remove(&pending_utxo_info.utxo_storage_key);
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L474-488)
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
```

**File:** contracts/satoshi-bridge/src/refund.rs (L254-258)
```rust
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );
```
