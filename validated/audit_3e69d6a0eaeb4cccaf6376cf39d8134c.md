### Title
Ignored `burn()` Result in `safe_mint_callback` Enables UTXO Reuse and Double-Minting — (File: `contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

---

### Summary

In `safe_mint_callback`, when the `safe_mint` cross-contract call fails (e.g., the recipient account is not registered), the bridge removes the UTXO from its `verified_deposit_utxo` guard and fires a `burn()` call with `.detach()` — no callback is attached to verify the burn succeeded. If the burn fails silently, the UTXO guard is gone but the minted nBTC tokens remain in the bridge's balance, leaving the same UTXO available for a second `safe_verify_deposit` submission that will mint a fresh batch of tokens.

---

### Finding Description

`safe_mint_callback` handles the failure branch of the `safe_verify_deposit` flow:

```rust
// contracts/satoshi-bridge/src/btc_light_client/deposit.rs  lines 438-455
} else {
    self.data_mut()
        .verified_deposit_utxo
        .remove(&pending_utxo_info.utxo_storage_key);   // (1) guard removed

    ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
        .with_static_gas(GAS_FOR_BURN_CALL)             // 5 TGas
        .burn(
            env::current_account_id(),
            mint_amount,
            relayer_account_id,
            U128(0),
        )
        .detach();                                       // (2) result ignored

    Promise::new(env::signer_account_id())
        .transfer(self.required_balance_for_safe_deposit())
        .detach();                                       // (3) result ignored
}
``` [1](#0-0) 

Step (1) removes the UTXO from `verified_deposit_utxo` unconditionally. Step (2) fires the compensating `burn()` call but discards its outcome entirely via `.detach()`. There is no callback that could detect a failed burn and re-insert the UTXO guard or otherwise roll back the state.

The `verify_safe_deposit_callback` that precedes this path inserts the UTXO into `verified_deposit_utxo` and requires the insert to succeed (i.e., the UTXO must not already be present):

```rust
// lines 399-403
require!(
    self.data_mut()
        .verified_deposit_utxo
        .insert(pending_utxo_info.utxo_storage_key.clone()),
    "Already deposit utxo"
);
``` [2](#0-1) 

Once `safe_mint_callback` removes the key, this guard is gone. A subsequent `safe_verify_deposit` call with the same BTC proof will pass the uniqueness check and mint a second batch of tokens.

The `burn()` function in the nbtc contract withdraws from the bridge's own balance:

```rust
// contracts/nbtc/src/lib.rs  lines 157-159
pub fn burn(&mut self, ...) {
    self.assert_bridge();
    self.token.internal_withdraw(&self.bridge_id, burn_amount.into());
``` [3](#0-2) 

Only 5 TGas is allocated to this cross-contract call (`GAS_FOR_BURN_CALL = Gas::from_tgas(5)`): [4](#0-3) 

If the call panics for any reason (gas exhaustion, nbtc contract state issue, future contract upgrade), the failure is invisible to the bridge — the UTXO guard has already been removed and the tokens remain in the bridge balance.

---

### Impact Explanation

If the detached `burn()` call fails:

1. The UTXO is no longer in `verified_deposit_utxo`.
2. The bridge holds nBTC tokens that were minted but never burned.
3. Any caller can re-submit the same BTC Merkle proof via `safe_verify_deposit`; the uniqueness check passes, and the bridge mints a second batch of nBTC for the same on-chain deposit.

This constitutes **unauthorized minting** — nBTC supply grows beyond the amount of BTC actually locked, breaking the 1:1 backing invariant.

**Impact: Critical** — unauthorized reminting / minting of nBTC without a corresponding BTC deposit.

---

### Likelihood Explanation

The `burn()` call is simple (a single storage write + event), and 5 TGas is normally sufficient. However:

- The result is **structurally ignored** regardless of outcome; any future nbtc contract change that adds logic to `burn()` could push it over the gas limit silently.
- An attacker who can predict or induce a gas-exhaustion scenario (e.g., by crafting the call context so that the remaining gas forwarded to the detached promise is below 5 TGas) can trigger the failure deterministically.
- The entry path (`safe_verify_deposit`) is fully public and requires only a valid BTC Merkle proof, which any bridge user possesses for their own deposit.

**Likelihood: Medium** — requires a valid BTC proof and a burn failure; the burn failure is not trivially forced today but the code provides no safety net if it ever occurs.

---

### Recommendation

Attach a callback to the `burn()` promise that checks `is_promise_success()`. On failure, re-insert the UTXO storage key into `verified_deposit_utxo` to restore the guard, preventing any retry from minting a second time. Pattern already used correctly elsewhere in the codebase (e.g., `verify_withdraw_burn_promise` → `verify_withdraw_burn_callback`):

```rust
// Correct pattern (burn.rs lines 17-29)
ext_nbtc::ext(config.nbtc_account_id.clone())
    .with_static_gas(GAS_FOR_BURN_CALL)
    .burn(...)
    .then(
        Self::ext(env::current_account_id())
            .with_static_gas(GAS_FOR_WITHDRAW_BURN_CALL_BACK)
            .verify_withdraw_burn_callback(...),
    )
``` [5](#0-4) 

Apply the same pattern in `safe_mint_callback`: replace `.detach()` with a `.then(Self::ext(...).safe_mint_burn_callback(pending_utxo_info.utxo_storage_key))` that re-inserts the UTXO key on failure.

---

### Proof of Concept

1. Attacker holds a valid BTC deposit (UTXO `U`) and its Merkle proof.
2. Attacker calls `safe_verify_deposit` with an **unregistered** NEAR account as recipient.
3. Bridge verifies proof → inserts `U` into `verified_deposit_utxo` → calls `safe_mint`.
4. `safe_mint` mints `N` nBTC to bridge balance; recipient account not found → returns `U128(0)`.
5. `safe_mint_callback` fires: `is_success = false` → removes `U` from `verified_deposit_utxo` → calls `burn(N).detach()`.
6. Attacker arranges for the burn to fail (e.g., gas exhaustion). Bridge now holds `N` extra nBTC; `U` is absent from `verified_deposit_utxo`.
7. Attacker registers their NEAR account.
8. Attacker re-submits the same Merkle proof via `safe_verify_deposit`.
9. `verify_safe_deposit_callback`: `U` not in `verified_deposit_utxo` → insert succeeds → `safe_mint` called again → mints another `N` nBTC → transfers to attacker.
10. Attacker receives `N` nBTC from a single BTC deposit; bridge supply is inflated by `N` unbacked tokens. [6](#0-5)

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L399-403)
```rust
        require!(
            self.data_mut()
                .verified_deposit_utxo
                .insert(pending_utxo_info.utxo_storage_key.clone()),
            "Already deposit utxo"
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L421-468)
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

        Event::VerifyDepositDetails {
            recipient_id: &recipient_id,
            mint_amount,
            protocol_fee: U128(0),
            relayer_account_id: env::signer_account_id(),
            relayer_fee: U128(0),
            success: is_success,
        }
        .emit();
        is_success
    }
```

**File:** contracts/nbtc/src/lib.rs (L150-159)
```rust
    pub fn burn(
        &mut self,
        burn_account_id: AccountId,
        burn_amount: U128,
        relayer_account_id: AccountId,
        relayer_fee: U128,
    ) {
        self.assert_bridge();
        self.token
            .internal_withdraw(&self.bridge_id, burn_amount.into());
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L6-6)
```rust
pub const GAS_FOR_BURN_CALL: Gas = Gas::from_tgas(5);
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L17-30)
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
    }
```
