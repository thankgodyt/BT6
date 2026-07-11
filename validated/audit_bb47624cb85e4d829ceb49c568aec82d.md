### Title
`safe_mint_callback` Misclassifies `safe_mint` Panic as Success, Permanently Locking User BTC Without Minting nBTC - (File: contracts/satoshi-bridge/src/btc_light_client/deposit.rs)

### Summary

The `safe_mint_callback` in the satoshi-bridge relies on `safe_mint` returning `U128(0)` to detect failure and trigger a rollback. However, `safe_mint` in the nbtc contract contains a `require!` guard that **panics** instead of returning `U128(0)` when `account_id == bridge_id`. The helper `is_refund_required()` treats any panic as "no refund" (`false`), so `safe_mint_callback` interprets the panic as success, adds the UTXO to the bridge's available set, and mints no nBTC. The user's BTC is permanently locked with no wrapped token issued.

### Finding Description

The `safe_verify_deposit` flow is designed so that `safe_mint` signals failure by returning `U128(0)`, which `safe_mint_callback` detects via `is_refund_required()` and uses to trigger rollback (remove UTXO from `verified_deposit_utxo`, burn any minted tokens, refund NEAR storage).

**`nbtc/src/lib.rs` — `safe_mint`:**

```rust
pub fn safe_mint(...) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(                                          // ← panics, never returns U128(0)
        account_id != self.bridge_id,
        "safe_mint: account_id must not be the bridge"
    );
    self.token.internal_deposit(&self.bridge_id, amount.into());
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));         // ← intended failure sentinel
    }
    ...
}
```

When `account_id == bridge_id`, the `require!` fires **before** `internal_deposit`, so no tokens are minted and the promise fails (panics).

**`deposit.rs` — `is_refund_required()`:**

```rust
fn is_refund_required() -> bool {
    match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
        Ok(value) => {
            if let Ok(amount) = near_sdk::serde_json::from_slice::<U128>(&value) {
                amount.0 == 0          // true  → rollback
            } else {
                false                  // false → treat as success
            }
        }
        Err(_) => false,               // ← panic lands here → treated as success
    }
}
```

A panic from `safe_mint` causes `promise_result_checked` to return `Err(_)`, so `is_refund_required()` returns `false`.

**`deposit.rs` — `safe_mint_callback`:**

```rust
pub fn safe_mint_callback(...) -> bool {
    let is_success = !is_refund_required();   // = !false = true  (wrong)
    if is_success {
        Event::UtxoAdded { ... }.emit();
        self.internal_set_utxo(...);          // UTXO added — no nBTC minted
    } else {
        // rollback: remove from verified_deposit_utxo, burn, refund NEAR
        // ← never reached
    }
    ...
}
```

The UTXO is permanently added to the bridge's available UTXO set. No nBTC is minted. No rollback occurs.

### Impact Explanation

A user who deposits BTC using a `DepositMsg` with `recipient_id = bridge_id` (and `safe_deposit: Some(...)`) will have their BTC permanently locked in the bridge's UTXO pool with zero nBTC issued. The UTXO enters the bridge's spendable set and will eventually be consumed by an unrelated withdrawal, effectively destroying the depositor's funds. This matches the allowed impact: **broken callback rollback / stuck bridge state / permanent locking of user funds**.

### Likelihood Explanation

`safe_verify_deposit` is a public function callable by any relayer. The `DepositMsg` is user-constructed and embedded in the deposit address derivation path. A user who mistakenly or deliberately sets `recipient_id` to the bridge's own account ID triggers the path. No privileged access is required. The bridge contract performs no pre-flight check on `recipient_id` before the cross-contract call chain reaches `safe_mint`.

### Recommendation

1. **In `safe_mint` (`nbtc/src/lib.rs`):** Replace the `require!` panic with an early `U128(0)` return, consistent with the "account not registered" path, so the failure sentinel propagates correctly:

```rust
if account_id == self.bridge_id {
    return PromiseOrValue::Value(U128(0));
}
```

2. **In `is_refund_required()` (`deposit.rs`):** Treat a failed promise (panic) as a refund-required condition rather than success, or at minimum remove the UTXO from `verified_deposit_utxo` so the deposit can be retried:

```rust
Err(_) => true,   // panic → treat as failure, trigger rollback
```

3. **In `internal_safe_verify_deposit_entry`:** Add an upfront `require!(deposit_msg.recipient_id != self.internal_config().bridge_id, "recipient cannot be bridge")` to reject the bad input before any state is mutated.

### Proof of Concept

1. User constructs `DepositMsg { recipient_id: bridge_account_id, safe_deposit: Some(SafeDepositMsg { msg: "" }), ... }`.
2. User sends BTC to the deposit address derived from this message.
3. Relayer calls `safe_verify_deposit(deposit_msg, tx_bytes, vout, proof)`.
4. `verify_safe_deposit_callback` marks the UTXO in `verified_deposit_utxo` and calls `safe_mint(bridge_id, amount, None)`.
5. `safe_mint` hits `require!(account_id != self.bridge_id)` → panics → promise fails.
6. `safe_mint_callback` is invoked; `is_refund_required()` returns `false` (Err branch).
7. `is_success = true` → `internal_set_utxo` is called → UTXO enters bridge's available set.
8. No nBTC is minted; no rollback; no NEAR refund.
9. User's BTC is permanently locked; the UTXO will be spent in a future unrelated withdrawal. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** contracts/nbtc/src/lib.rs (L107-116)
```rust
        self.assert_bridge();
        require!(
            account_id != self.bridge_id,
            "safe_mint: account_id must not be the bridge"
        );
        self.token.internal_deposit(&self.bridge_id, amount.into());

        if self.token.accounts.get(&account_id).is_none() {
            return PromiseOrValue::Value(U128(0));
        }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L421-456)
```rust
    #[private]
    pub fn safe_mint_callback(
        &mut self,
        recipient_id: AccountId,
        mint_amount: U128,
        pending_utxo_info: PendingUTXOInfo,
    ) -> bool {
        let is_success = !is_refund_required();
        let relayer_account_id = env::signer_account_id();

        if is_success {
            Event::UtxoAdded {
                utxo_storage_keys: vec![pending_utxo_info.utxo_storage_key.clone()],
                balances: Some(vec![U128(pending_utxo_info.utxo.balance.into())]),
            }
            .emit();
            self.internal_set_utxo(&pending_utxo_info.utxo_storage_key, pending_utxo_info.utxo);
        } else {
            self.data_mut()
                .verified_deposit_utxo
                .remove(&pending_utxo_info.utxo_storage_key);

            ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
                .with_static_gas(GAS_FOR_BURN_CALL)
                .burn(
                    env::current_account_id(),
                    mint_amount,
                    relayer_account_id,
                    U128(0),
                )
                .detach();

            Promise::new(env::signer_account_id())
                .transfer(self.required_balance_for_safe_deposit())
                .detach();
        }
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
