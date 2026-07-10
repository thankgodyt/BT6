### Title
Unchecked `.detach()` Burn Call in `safe_mint_callback` Leaves Unbacked nBTC in Bridge Balance — (File: `contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

### Summary

In the `safe_mint_callback` failure path, the bridge fires a `burn` cross-contract call using `.detach()` with no callback. If that burn fails for any reason, the nBTC tokens minted to the bridge's own account during `safe_mint` are never destroyed, permanently inflating the nBTC total supply beyond the amount of BTC actually locked.

### Finding Description

The `safe_verify_deposit` flow calls `safe_mint` on the nBTC contract. `safe_mint` unconditionally mints `mint_amount` tokens to the bridge's own account (`self.bridge_id`) first, then attempts to transfer them to the recipient. If the recipient is not registered, `safe_mint` returns `U128(0)` and the tokens remain in the bridge's balance.

`safe_mint_callback` detects this via `is_refund_required()` and enters the failure branch:

```rust
} else {
    self.data_mut()
        .verified_deposit_utxo
        .remove(&pending_utxo_info.utxo_storage_key);

    ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
        .with_static_gas(GAS_FOR_BURN_CALL)   // only 5 TGas
        .burn(
            env::current_account_id(),
            mint_amount,
            relayer_account_id,
            U128(0),
        )
        .detach();   // ← result is NEVER checked
    ...
}
``` [1](#0-0) 

The `burn` call is the sole rollback mechanism for the failed mint. Because it is `.detach()`-ed, there is no callback to detect whether it succeeded or panicked. The gas budget allocated is `GAS_FOR_BURN_CALL = Gas::from_tgas(5)`, which is very tight for a function that must deserialize contract state, call `internal_withdraw`, and serialize state back. [2](#0-1) 

By contrast, every other burn call in the codebase (e.g., `verify_withdraw_burn_promise`, `verify_active_utxo_management_burn_promise`) is followed by a proper callback that checks `is_promise_success()` and rolls back state on failure. [3](#0-2) 

The `safe_mint` function in the nBTC contract always deposits to the bridge's account before checking registration:

```rust
self.token.internal_deposit(&self.bridge_id, amount.into());

if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));
}
``` [4](#0-3) 

So on every unregistered-recipient deposit, `mint_amount` nBTC is created in the bridge's balance and the only mechanism to destroy it is the detached, unchecked burn.

### Impact Explanation

If the detached `burn` call fails (gas exhaustion at 5 TGas, a panic inside `internal_withdraw`, or any other runtime error), the bridge's nBTC balance is permanently inflated by `mint_amount`. The total nBTC supply exceeds the amount of BTC actually locked in the bridge's UTXO set. There is no recovery path: the UTXO is removed from `verified_deposit_utxo` and never added to the available UTXO set, and no event or state flag records the failed burn for operator intervention.

This constitutes a broken callback rollback and a stuck bridge state — the bridge holds unbacked nBTC with no on-chain mechanism to detect or correct it.

**Allowed impact matched:** Medium — broken callback rollback; stuck bridge state requiring operator intervention; supply above backed BTC.

### Likelihood Explanation

The trigger condition (recipient not registered on nBTC) is a normal, publicly reachable scenario — any relayer submitting a `safe_verify_deposit` for a user who has not called `storage_deposit` on the nBTC contract will hit this path. The burn failing is less common but realistic: 5 TGas is a very low budget for a storage-modifying cross-contract call, and any concurrent state pressure or future contract growth could push it over the limit. Because the call is detached, even a single silent failure permanently corrupts the supply invariant.

### Recommendation

Replace the detached burn with a chained callback that checks `is_promise_success()` and, on failure, re-inserts the UTXO into `verified_deposit_utxo` or records the unbacked amount in a recoverable `lost_found`-style map — mirroring the pattern already used in `transfer_nbtc_callback`. [5](#0-4) 

Additionally, increase `GAS_FOR_BURN_CALL` in the `safe_mint_callback` failure path to match the budget used in the withdrawal burn path.

### Proof of Concept

1. Alice sends BTC to her deposit address.
2. A relayer calls `safe_verify_deposit` with a valid Merkle proof. Alice has never called `storage_deposit` on the nBTC contract.
3. `verify_safe_deposit_callback` verifies the proof, inserts the UTXO key into `verified_deposit_utxo`, and calls `safe_mint(alice, mint_amount, msg)`.
4. `safe_mint` executes `internal_deposit(&bridge_id, mint_amount)` — bridge's nBTC balance increases by `mint_amount`. Because Alice is unregistered, it returns `U128(0)`.
5. `safe_mint_callback` detects `is_refund_required() == true`, removes the UTXO from `verified_deposit_utxo`, and fires `burn(bridge_id, mint_amount, ...).detach()`.
6. The burn receipt executes but panics (e.g., 5 TGas exhausted). Because it is detached, the panic is silently discarded.
7. Result: bridge's nBTC balance is permanently `mint_amount` higher than the BTC locked. The UTXO is neither in the available set nor in `verified_deposit_utxo`. The supply invariant is broken with no on-chain recovery path. [6](#0-5) [7](#0-6)

### Citations

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

**File:** contracts/nbtc/src/lib.rs (L112-116)
```rust
        self.token.internal_deposit(&self.bridge_id, amount.into());

        if self.token.accounts.get(&account_id).is_none() {
            return PromiseOrValue::Value(U128(0));
        }
```

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L54-75)
```rust
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
