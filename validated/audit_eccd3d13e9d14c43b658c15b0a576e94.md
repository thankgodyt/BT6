### Title
Unchecked Return Values on Detached `burn()` and NEAR `transfer()` Promises in `safe_mint_callback` - (File: `contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

---

### Summary

In `safe_mint_callback`, when `safe_mint` returns `U128(0)` (indicating the downstream `ft_on_transfer` consumed zero tokens and a refund is required), the bridge fires two critical promises with `.detach()`: a `burn()` call to destroy the minted nBTC from the bridge's balance, and a NEAR `transfer()` to refund the relayer's storage deposit. Neither result is ever checked. If either promise fails silently, the bridge's state is left inconsistent with no recovery path.

---

### Finding Description

In `safe_mint_callback` (the callback for the `safe_verify_deposit` flow), when `is_success` is `false`, the following two promises are dispatched with `.detach()`:

```rust
// contracts/satoshi-bridge/src/btc_light_client/deposit.rs, lines 443–455
ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
    .with_static_gas(GAS_FOR_BURN_CALL)
    .burn(
        env::current_account_id(),
        mint_amount,
        relayer_account_id,
        U128(0),
    )
    .detach();                                          // ← result never checked

Promise::new(env::signer_account_id())
    .transfer(self.required_balance_for_safe_deposit())
    .detach();                                          // ← result never checked
``` [1](#0-0) 

Before these detached calls are made, the UTXO is already removed from `verified_deposit_utxo`:

```rust
self.data_mut()
    .verified_deposit_utxo
    .remove(&pending_utxo_info.utxo_storage_key);
``` [2](#0-1) 

The `safe_mint` flow in the nBTC contract first deposits nBTC to the bridge's own balance, then calls `ft_transfer_call` to the recipient. If `ft_on_transfer` returns `0`, `ft_resolve_transfer` refunds the tokens back to the bridge's balance. At that point the bridge holds live nBTC that must be burned. The detached `burn()` is the only mechanism to do so. [3](#0-2) 

The `burn()` function in the nBTC contract calls `internal_withdraw` on the bridge's balance. If the bridge's nBTC balance has been reduced by a concurrent transaction between `safe_mint_callback` completing and the detached `burn()` executing (NEAR cross-contract calls are not atomic), `internal_withdraw` will panic and the burn silently fails. [4](#0-3) 

By contrast, the analogous `internal_transfer_nbtc` used elsewhere in the bridge correctly attaches a `transfer_nbtc_callback` that handles failure by crediting `lost_found`, demonstrating the project is aware of the need to handle transfer failures: [5](#0-4) 

---

### Impact Explanation

**If `burn()` fails silently:**
- The UTXO key has already been removed from `verified_deposit_utxo`, so the BTC UTXO can never be re-deposited or refunded — it is permanently stranded.
- The nBTC tokens remain in the bridge's own balance, inflating the bridge's nBTC holdings relative to its tracked UTXO set. These tokens are not backed by any reachable BTC UTXO.
- The bridge's `cur_available_protocol_fee` and related accounting are unaffected, so the discrepancy is invisible to the protocol's own invariant checks.

**If the NEAR `transfer()` fails silently:**
- The relayer who attached NEAR for storage (enforced by `require!(env::attached_deposit() >= self.required_balance_for_safe_deposit(), ...)`) loses that deposit with no recovery path and no event emitted. [6](#0-5) 

This matches the **Medium** impact class: harmful smart-contract behavior without direct theft — specifically, permanent locking of a BTC UTXO and inflation of the bridge's nBTC balance relative to its backed supply.

---

### Likelihood Explanation

The failure path is reachable by any public user:

1. A user calls `safe_verify_deposit` with a valid BTC proof and a `msg` whose downstream `ft_on_transfer` returns `0` (e.g., the Omni Bridge receiver rejects the transfer for any reason, or the recipient account is not registered).
2. `safe_mint` returns `U128(0)`, triggering the `is_success = false` branch.
3. The detached `burn()` and NEAR `transfer()` are fired.

The `burn()` failure specifically requires the bridge's nBTC balance to be insufficient at the moment the detached call executes. Because NEAR cross-contract calls are separate transactions, any concurrent bridge operation that reduces the bridge's nBTC balance (e.g., a concurrent `verify_withdraw` burn) between `safe_mint_callback` and the detached `burn()` can cause this. The probability is low under normal load but non-zero and grows with bridge activity.

---

### Recommendation

Replace the detached `burn()` with a chained callback that checks success and, on failure, re-inserts the UTXO key into `verified_deposit_utxo` and records the unbacked nBTC in a recovery ledger (analogous to `lost_found`). Replace the detached NEAR `transfer()` with a chained callback that records the owed amount for manual recovery if the transfer fails.

```rust
// Instead of:
ext_nbtc::ext(...).burn(...).detach();

// Use:
ext_nbtc::ext(...).burn(...).then(
    Self::ext(env::current_account_id())
        .with_static_gas(GAS_FOR_BURN_CALLBACK)
        .safe_mint_burn_callback(pending_utxo_info.utxo_storage_key, mint_amount),
);
```

The callback should re-insert the UTXO key and emit an alert event if `is_promise_success()` returns false.

---

### Proof of Concept

1. Deploy the bridge and nBTC contracts on NEAR testnet.
2. Register a receiver contract whose `ft_on_transfer` always returns `"0"` (refund all).
3. Submit a valid BTC deposit proof via `safe_verify_deposit` with `msg` pointing to the rejecting receiver.
4. Observe `safe_mint_callback` executes with `is_success = false`.
5. Before the detached `burn()` transaction executes, submit a concurrent `verify_withdraw` that drains the bridge's nBTC balance to zero.
6. The detached `burn()` panics inside `internal_withdraw` (insufficient balance) and is silently dropped.
7. Confirm: `verified_deposit_utxo` no longer contains the UTXO key (BTC is stranded), but the bridge's nBTC balance still holds `mint_amount` tokens that are not backed by any tracked UTXO. [7](#0-6) [3](#0-2)

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L181-184)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_safe_deposit(),
            "Insufficient deposit for storage"
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

**File:** contracts/nbtc/src/lib.rs (L101-124)
```rust
    pub fn safe_mint(
        &mut self,
        account_id: AccountId,
        amount: U128,
        msg: Option<String>,
    ) -> PromiseOrValue<U128> {
        self.assert_bridge();
        require!(
            account_id != self.bridge_id,
            "safe_mint: account_id must not be the bridge"
        );
        self.token.internal_deposit(&self.bridge_id, amount.into());

        if self.token.accounts.get(&account_id).is_none() {
            return PromiseOrValue::Value(U128(0));
        }

        if let Some(msg) = msg {
            self.ft_transfer_call(account_id, amount, None, msg)
        } else {
            self.ft_transfer(account_id, amount, None);
            PromiseOrValue::Value(amount)
        }
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

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L23-75)
```rust
    pub fn internal_transfer_nbtc(&self, account_id: &AccountId, amount: u128) -> Promise {
        ext_ft_core::ext(self.internal_config().nbtc_account_id.clone())
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .with_static_gas(GAS_FOR_TOKEN_TRANSFER)
            .ft_transfer(account_id.clone(), amount.into(), None)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_AFTER_TOKEN_TRANSFER)
                    .transfer_nbtc_callback(account_id.clone(), amount.into()),
            )
    }
}

#[near]
impl Contract {
    #[private]
    pub fn withdraw_protocol_fee_callback(&mut self, amount: U128) -> bool {
        let promise_success = is_promise_success();
        let event = Event::WithdrawBridgeProtocolFee {
            amount,
            success: promise_success,
        };
        if !promise_success {
            self.data_mut().cur_available_protocol_fee += amount.0;
            self.data_mut().acc_claimed_protocol_fee -= amount.0;
        }
        event.emit();
        promise_success
    }

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
