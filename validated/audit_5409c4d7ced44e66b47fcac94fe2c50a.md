### Title
Detached Burn Call with Insufficient Gas in `safe_mint_callback` Enables Double-Minting via UTXO Re-use — (File: `contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

### Summary

In `safe_mint_callback`, when the `safe_mint` receiver returns 0 (tokens unused), the contract removes the UTXO from `verified_deposit_utxo` and then fires a `burn` cross-contract call with only 5 TGas using `.detach()`. If the burn fails silently, the minted nBTC remains in the bridge contract while the UTXO is no longer replay-protected, allowing a relayer to re-submit the same deposit proof and mint a second batch of nBTC against the same BTC.

### Finding Description

The `safe_mint_callback` function handles the failure branch of a `safe_mint` call (i.e., when the downstream `ft_on_transfer` receiver returns 0, signalling it did not consume the tokens):

```rust
// contracts/satoshi-bridge/src/btc_light_client/deposit.rs, lines 438-455
} else {
    self.data_mut()
        .verified_deposit_utxo
        .remove(&pending_utxo_info.utxo_storage_key);   // ← UTXO replay-guard removed

    ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
        .with_static_gas(GAS_FOR_BURN_CALL)              // ← only 5 TGas
        .burn(
            env::current_account_id(),
            mint_amount,
            relayer_account_id,
            U128(0),
        )
        .detach();                                        // ← result never checked

    Promise::new(env::signer_account_id())
        .transfer(self.required_balance_for_safe_deposit())
        .detach();
}
```

`GAS_FOR_BURN_CALL` is defined as `Gas::from_tgas(5)`. This is the NEAR analog of Solidity's deprecated `transfer()`: a fixed, minimal gas budget is forwarded to a cross-contract call, and the outcome is silently discarded via `.detach()`.

The ordering of operations is the root cause:

1. **The UTXO replay-guard is removed first** (`verified_deposit_utxo.remove(...)`) — unconditionally, before the burn is confirmed.
2. **The burn is fired with 5 TGas and `.detach()`** — if the nBTC `burn` function requires more gas (storage writes, events, NEP-141 bookkeeping), the call runs out of gas and fails. Because the promise is detached, no callback observes the failure; the minted tokens remain in the bridge contract's nBTC balance.
3. **The UTXO is now unguarded.** A relayer can immediately call `verify_deposit` (the non-safe path) with the same `tx_bytes`/`vout`. `verify_deposit_callback` re-inserts the key into `verified_deposit_utxo` and calls `internal_mint_promise`, minting a second batch of nBTC to the original recipient.

In every other burn site in the codebase the result is observed via a callback:

```rust
// contracts/satoshi-bridge/src/nbtc/burn.rs, lines 17-29
ext_nbtc::ext(config.nbtc_account_id.clone())
    .with_static_gas(GAS_FOR_BURN_CALL)
    .burn(...)
    .then(
        Self::ext(env::current_account_id())
            .with_static_gas(GAS_FOR_WITHDRAW_BURN_CALL_BACK)
            .verify_withdraw_burn_callback(...)   // ← failure handled
    )
```

Only the `safe_mint_callback` failure branch uses `.detach()`, making it the sole site where a burn failure is undetectable.

### Impact Explanation

If the detached burn fails, the bridge has:
- Minted `mint_amount` nBTC (via `safe_mint`) that remain in the bridge contract's own balance.
- Removed the UTXO from `verified_deposit_utxo`, so the same BTC proof can be re-submitted.
- A subsequent `verify_deposit` call mints another `mint_amount` nBTC to the recipient.

Net result: 2× nBTC in circulation backed by 1× BTC — unauthorized minting / permanent supply inflation. This matches the **Critical** impact tier: *Unauthorized minting of nBTC*.

### Likelihood Explanation

The trigger requires two conditions:

1. **`safe_mint` receiver returns 0.** This is the designed failure mode of the `safe_deposit` path — any receiver contract that panics, rejects the transfer, or returns the full amount causes `is_refund_required()` to return `true`. An attacker can deploy a receiver contract that always returns 0 from `ft_on_transfer` and use it as the `msg` target.

2. **The detached burn fails.** `GAS_FOR_BURN_CALL = 5 TGas` is a tight budget. The nBTC `burn` function must perform at minimum: argument deserialization, balance lookup, balance update, storage write, and event emission. Under NEAR's gas pricing, storage-touching operations alone can consume several TGas. Any future nBTC upgrade that adds a callback or additional bookkeeping to `burn` would push it over 5 TGas. Even today, if the nBTC contract's `burn` is implemented with a cross-contract callback (e.g., to notify a hook), 5 TGas is provably insufficient.

An unprivileged user controls the `msg` field of `safe_verify_deposit`, which determines the receiver. This is a fully public, attacker-controlled entry path.

### Recommendation

Mirror the pattern used in every other burn site: replace the detached burn with a chained callback that re-inserts the UTXO into `verified_deposit_utxo` on failure, or — at minimum — do not remove the UTXO from `verified_deposit_utxo` until the burn callback confirms success.

```rust
// Instead of:
self.data_mut().verified_deposit_utxo.remove(&pending_utxo_info.utxo_storage_key);
ext_nbtc::ext(...).with_static_gas(GAS_FOR_BURN_CALL).burn(...).detach();

// Do:
ext_nbtc::ext(...).with_static_gas(GAS_FOR_BURN_CALL).burn(...)
    .then(
        Self::ext(env::current_account_id())
            .with_static_gas(GAS_FOR_SAFE_MINT_BURN_CALLBACK)
            .safe_mint_burn_callback(pending_utxo_info.utxo_storage_key, mint_amount)
    );
// In safe_mint_burn_callback: only remove from verified_deposit_utxo if burn succeeded;
// if burn failed, leave the UTXO in verified_deposit_utxo (deposit is blocked but not double-spendable).
```

Also increase `GAS_FOR_BURN_CALL` to a value that accounts for the full nBTC burn execution path, consistent with the gas budgets used in `verify_withdraw_burn_promise` and `verify_active_utxo_management_burn_promise`.

### Proof of Concept

1. Attacker deploys a NEAR contract `evil.near` whose `ft_on_transfer` always returns `"0"` (full refund).
2. Attacker calls `safe_verify_deposit` with a valid BTC deposit proof and `msg` pointing to `evil.near`.
3. Bridge calls `safe_mint` → nBTC mints tokens to bridge, calls `ft_transfer_call` to `evil.near` → `evil.near` returns `"0"`.
4. `safe_mint_callback` fires: `is_refund_required()` = true.
   - `verified_deposit_utxo.remove(utxo_key)` — UTXO guard dropped.
   - `burn(...).detach()` — if burn runs out of 5 TGas, fails silently; minted tokens remain in bridge.
5. Attacker (or any relayer) immediately calls `verify_deposit` with the same `tx_bytes`/`vout`.
6. `verify_deposit_callback` re-inserts `utxo_key` into `verified_deposit_utxo` and calls `internal_mint_promise`.
7. nBTC mints a second `mint_amount` to the attacker's `recipient_id`.
8. Result: 2× nBTC minted for 1× BTC deposited.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L369-383)
```rust
        require!(
            self.data_mut()
                .verified_deposit_utxo
                .insert(pending_utxo_info.utxo_storage_key.clone()),
            "Already deposit utxo"
        );
        self.internal_mint_promise(
            recipient_id,
            mint_amount,
            protocol_fee,
            relayer_fee,
            pending_utxo_info,
            post_actions,
        )
        .into()
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L438-455)
```rust
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
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L6-6)
```rust
pub const GAS_FOR_BURN_CALL: Gas = Gas::from_tgas(5);
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L17-29)
```rust
        ext_nbtc::ext(config.nbtc_account_id.clone())
            .with_static_gas(GAS_FOR_BURN_CALL)
            .burn(
                btc_pending_info.account_id.clone(),
                btc_pending_info.burn_amount.into(),
                env::signer_account_id(),
                relayer_fee.into(),
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_WITHDRAW_BURN_CALL_BACK)
                    .verify_withdraw_burn_callback(tx_id, protocol_fee.into(), relayer_fee.into()),
            )
```
