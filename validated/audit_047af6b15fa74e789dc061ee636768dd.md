### Title
Unchecked Return Value of `burn()` in `safe_mint_callback` Enables Unbacked nBTC Supply Inflation — (File: `contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

---

### Summary

In `safe_mint_callback`, when the `safe_mint` cross-contract call returns `U128(0)` (indicating the receiver did not consume the minted tokens), the bridge fires a `burn()` call on the nBTC contract using `.detach()`. The result of this burn is never checked. If the burn fails silently, the minted nBTC tokens remain in circulation while the UTXO is simultaneously removed from `verified_deposit_utxo`, leaving the bridge in an inconsistent state that permits re-submission of the same deposit.

---

### Finding Description

The `safe_mint_callback` function handles the case where `safe_mint` did not transfer tokens to the receiver (i.e., `is_refund_required()` returns `true`). In this branch, the bridge must burn the already-minted tokens to maintain the supply invariant. However, the burn call is issued with `.detach()`:

```rust
// contracts/satoshi-bridge/src/btc_light_client/deposit.rs, lines 443–451
ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
    .with_static_gas(GAS_FOR_BURN_CALL)
    .burn(
        env::current_account_id(),
        mint_amount,
        relayer_account_id,
        U128(0),
    )
    .detach();
```

`.detach()` means no callback is registered and the promise result is never inspected. If the burn fails for any reason (e.g., the nBTC contract panics, the bridge lacks burn authorization, or `GAS_FOR_BURN_CALL = 5 tgas` is insufficient), the failure is invisible to the bridge contract.

Immediately before this burn, the UTXO is removed from the replay-protection set:

```rust
// contracts/satoshi-bridge/src/btc_light_client/deposit.rs, lines 439–441
self.data_mut()
    .verified_deposit_utxo
    .remove(&pending_utxo_info.utxo_storage_key);
```

This removal is correct when the burn succeeds (the UTXO should be available for re-deposit). But when the burn fails silently, the state is:
- The nBTC tokens from the first `safe_mint` remain in the bridge contract's account (unbacked).
- The UTXO is no longer in `verified_deposit_utxo`, so the same UTXO can be re-submitted via `safe_verify_deposit`.
- A second successful deposit verification for the same UTXO mints a second batch of nBTC tokens, resulting in double-minting.

Contrast this with the analogous `internal_transfer_nbtc` call in `verify_withdraw_burn_callback` (burn.rs line 140), which correctly uses a callback (`transfer_nbtc_callback`) that handles failure via the `lost_found` accounting map. The `safe_mint_callback` burn has no such recovery path.

---

### Impact Explanation

**Medium / Critical boundary.** In the base case (burn fails, no re-submission), the nBTC total supply exceeds the BTC backing by `mint_amount` — permanent supply inflation without direct user theft. If an attacker can trigger the burn failure and then re-submit the same UTXO proof, the same BTC deposit mints nBTC twice, constituting unauthorized minting of unbacked nBTC. The UTXO replay guard (`verified_deposit_utxo`) is the only protection against double-minting, and it is cleared before the burn result is known.

---

### Likelihood Explanation

The `safe_mint` path is publicly reachable by any NEAR account that submits a valid BTC SPV proof via `safe_verify_deposit`. The burn failure requires the nBTC contract to reject or run out of gas on the burn call. `GAS_FOR_BURN_CALL` is only 5 tgas — a tight budget for a cross-contract call that may involve storage operations. Any future complexity added to the nBTC `burn` function, or a transient gas-pricing change, could push it over the limit. Because the failure is silent, there is no on-chain signal and no operator intervention is triggered.

---

### Recommendation

Replace the detached burn with a chained callback that verifies success and, on failure, re-inserts the UTXO storage key into `verified_deposit_utxo` (to prevent re-deposit) and emits an error event for operator recovery. Pattern after the existing `transfer_nbtc_callback` in `token_transfer.rs` which correctly handles failure:

```rust
// Instead of .detach(), chain a callback:
ext_nbtc::ext(...)
    .with_static_gas(GAS_FOR_BURN_CALL)
    .burn(env::current_account_id(), mint_amount, relayer_account_id, U128(0))
    .then(
        Self::ext(env::current_account_id())
            .with_static_gas(GAS_FOR_SAFE_MINT_BURN_CALLBACK)
            .safe_mint_burn_callback(pending_utxo_info.utxo_storage_key),
    );
```

In `safe_mint_burn_callback`, if `is_promise_success()` is false, re-insert the key into `verified_deposit_utxo` to block re-deposit and emit a recoverable error event.

---

### Proof of Concept

1. Attacker submits a valid BTC SPV proof for UTXO `U` via `safe_verify_deposit`. The receiver contract's `ft_on_transfer` is crafted to return `U128(0)`.
2. `verify_safe_deposit_callback` runs: `verified_deposit_utxo.insert(U)` succeeds; `safe_mint` is called.
3. `safe_mint_callback` runs: `is_refund_required()` → `true`. `verified_deposit_utxo.remove(U)` executes. `burn(...).detach()` is fired but fails (e.g., gas exhaustion at 5 tgas). Failure is invisible.
4. nBTC tokens equal to `mint_amount` remain in the bridge contract's account. `U` is no longer in `verified_deposit_utxo`.
5. Attacker re-submits the same SPV proof for UTXO `U`. `verify_safe_deposit_callback` runs again: `verified_deposit_utxo.insert(U)` succeeds (key was removed in step 3). `safe_mint` is called again.
6. This time the receiver accepts the tokens. `safe_mint_callback` runs: `is_success = true`. UTXO `U` is added to the bridge UTXO set.
7. Result: two batches of nBTC minted for one BTC UTXO. The first batch (step 3) is unbacked and circulating; the second batch (step 6) is backed. Net supply inflation = `mint_amount`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L471-489)
```rust
/// Refund only if `safe_mint` returned 0. Any other outcome (non-zero
/// amount, unparseable payload, panic) is treated as "UTXO spent, no
/// refund" — for safety, to avoid a potential double spend.
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

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L53-75)
```rust
    #[private]
    pub fn transfer_nbtc_callback(&mut self, account_id: AccountId, amount: U128) -> bool {
        let promise_success = is_promise_success();
        let event = Event::TransferNbtc {
            account_id: &account_id,
            amount,
            success: promise_success,
        };
        if !promise_success {
            self.data_mut()
                .lost_found
                .entry(account_id.clone())
                .and_modify(|v| *v += amount.0)
                .or_insert(amount.0);
            Event::LostFoundNbtc {
                account_id: &account_id,
                amount,
            }
            .emit();
        }
        event.emit();
        promise_success
    }
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L6-7)
```rust
pub const GAS_FOR_BURN_CALL: Gas = Gas::from_tgas(5);
pub const GAS_FOR_WITHDRAW_BURN_CALL_BACK: Gas = Gas::from_tgas(20);
```
