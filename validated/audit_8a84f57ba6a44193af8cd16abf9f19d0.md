### Title
Unhandled `burn()` Promise Result in `safe_mint_callback` Enables Silent nBTC Supply Inflation - (File: contracts/satoshi-bridge/src/btc_light_client/deposit.rs)

### Summary
In the `safe_mint_callback` function, when `safe_mint` returns `U128(0)` (recipient account not registered), the bridge fires a `burn()` cross-contract call on the nbtc contract using `.detach()`. Because `.detach()` discards the Promise result entirely, a failure of the `burn()` call is never detected. The UTXO has already been removed from `verified_deposit_utxo` before the burn is dispatched, leaving the bridge in an inconsistent state: extra nBTC tokens remain in the bridge account and the UTXO is no longer replay-protected.

### Finding Description
The `safe_mint` function in `contracts/nbtc/src/lib.rs` always mints tokens to the bridge account first (`internal_deposit` at line 112), then checks whether the recipient is registered. If the recipient is unregistered it returns `PromiseOrValue::Value(U128(0))` immediately without transferring the tokens to the recipient. [1](#0-0) 

Back in the bridge, `safe_mint_callback` interprets this `U128(0)` result as a refund signal via `is_refund_required()`, removes the UTXO from `verified_deposit_utxo`, and then calls `burn()` with `.detach()` to undo the minting: [2](#0-1) 

The `.detach()` call means the bridge never observes whether `burn()` succeeded or failed. If the burn fails silently:

1. The bridge account retains the extra nBTC tokens that were minted but never burned — nBTC supply exceeds backed BTC.
2. The UTXO key is absent from `verified_deposit_utxo`, so the replay-protection check in `verify_deposit_callback` (`require!(self.data_mut().verified_deposit_utxo.insert(...))`) would pass for the same UTXO, allowing it to be re-deposited and minted a second time. [3](#0-2) 

The `burn()` function in the nbtc contract is straightforward and should succeed under normal conditions, but the absence of any error-handling callback means any failure (gas exhaustion, nbtc contract panic, storage issue) is permanently silent with no recovery path. [4](#0-3) 

### Impact Explanation
If the detached `burn()` call fails, the nBTC total supply permanently exceeds the amount of BTC held by the bridge (supply inflation). Additionally, because the UTXO is removed from `verified_deposit_utxo` before the burn is confirmed, the same Bitcoin UTXO can be re-submitted through the normal `verify_deposit` path, triggering a second mint for the same on-chain BTC — unauthorized minting. This matches the allowed impact: *permanent burning below backed supply* and *unauthorized minting of nBTC*.

### Likelihood Explanation
The failure path is reachable by any unprivileged user: call `safe_verify_deposit` with a recipient account that has no storage registration on the nbtc contract. The `safe_mint` will return `U128(0)`, triggering the detached burn. While the burn itself is unlikely to fail under normal network conditions (the bridge account holds the tokens and 5 TGas is allocated), the complete absence of a callback means any transient failure — including gas exhaustion under load, a concurrent nbtc contract upgrade, or an unexpected panic — produces a permanently undetected inconsistency with no operator alert and no automatic recovery. [5](#0-4) 

### Recommendation
Replace the `.detach()` pattern with a chained callback that verifies the burn succeeded. If the burn fails, the callback should re-insert the UTXO key into `verified_deposit_utxo` to restore replay protection and emit an error event for operator intervention:

```rust
ext_nbtc::ext(config.nbtc_account_id.clone())
    .with_static_gas(GAS_FOR_BURN_CALL)
    .burn(env::current_account_id(), mint_amount, relayer_account_id, U128(0))
    .then(
        Self::ext(env::current_account_id())
            .with_static_gas(GAS_FOR_SAFE_MINT_BURN_CALLBACK)
            .safe_mint_burn_callback(pending_utxo_info.utxo_storage_key.clone()),
    );
```

The `safe_mint_burn_callback` should check `is_promise_success()` and, on failure, re-insert the UTXO into `verified_deposit_utxo` and emit a recoverable error event.

### Proof of Concept
1. Alice has BTC at a bridge deposit address but her NEAR account (`alice.near`) has no storage registration on the nbtc contract.
2. A relayer calls `safe_verify_deposit` with `recipient_id = alice.near`.
3. The light-client proof passes; `verify_safe_deposit_callback` calls `safe_mint(alice.near, amount, None)`.
4. Inside `safe_mint`, `internal_deposit(&bridge_id, amount)` mints tokens to the bridge account; then `accounts.get(&alice.near).is_none()` is true, so `U128(0)` is returned immediately.
5. `safe_mint_callback` sees `U128(0)`, sets `is_success = false`, removes the UTXO from `verified_deposit_utxo`, and fires `burn(...).detach()`.
6. If the `burn()` call fails for any reason (gas, panic), the bridge account retains the extra nBTC and the UTXO is no longer in `verified_deposit_utxo`.
7. The relayer (or attacker) now calls `verify_deposit` with the same UTXO. The `verified_deposit_utxo.insert(...)` check passes (UTXO was removed in step 5), a second mint is issued, and the UTXO is added to the active UTXO set — double-mint achieved with no additional BTC deposited. [6](#0-5)

### Citations

**File:** contracts/nbtc/src/lib.rs (L112-116)
```rust
        self.token.internal_deposit(&self.bridge_id, amount.into());

        if self.token.accounts.get(&account_id).is_none() {
            return PromiseOrValue::Value(U128(0));
        }
```

**File:** contracts/nbtc/src/lib.rs (L150-177)
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
        if relayer_fee.0 > 0 {
            if self.token.accounts.get(&relayer_account_id).is_none() {
                self.token.internal_register_account(&relayer_account_id);
            }
            self.token.internal_transfer(
                &self.bridge_id,
                &relayer_account_id,
                relayer_fee.into(),
                None,
            );
        }
        near_contract_standards::fungible_token::events::FtBurn {
            owner_id: &burn_account_id,
            amount: burn_amount,
            memo: None,
        }
        .emit();
    }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L369-374)
```rust
        require!(
            self.data_mut()
                .verified_deposit_utxo
                .insert(pending_utxo_info.utxo_storage_key.clone()),
            "Already deposit utxo"
        );
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
