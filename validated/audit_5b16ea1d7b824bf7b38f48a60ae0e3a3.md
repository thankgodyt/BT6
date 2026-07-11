### Title
Unchecked `burn()` Cross-Contract Call Result in `safe_mint_callback` Causes Unbacked nBTC Supply Inflation — (File: `contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

---

### Summary

In `safe_mint_callback`, when `safe_mint` signals failure by returning `U128(0)` (recipient account not registered), the bridge fires a compensating `burn()` call using `.detach()`. Because `.detach()` discards the promise result entirely, any failure of that burn call goes undetected and unhandled. The nBTC tokens that were minted to the bridge account during `safe_mint` then remain permanently in the bridge's balance, inflating the nBTC total supply beyond what is backed by real BTC.

---

### Finding Description

The `safe_verify_deposit` flow calls `safe_mint` on the nBTC contract. Inside `safe_mint` (`contracts/nbtc/src/lib.rs` lines 112–123), tokens are first unconditionally minted to the bridge account via `internal_deposit`, and only then is the recipient's registration checked. If the recipient is unregistered, `safe_mint` returns `U128(0)` without transferring the tokens to the recipient — but the tokens already exist in the bridge's balance.

Back in `safe_mint_callback` (`contracts/satoshi-bridge/src/btc_light_client/deposit.rs` lines 428–456), the bridge detects the failure via `is_refund_required()` and attempts to destroy those orphaned tokens by calling `burn()`. However, this call is made with `.detach()`:

```rust
ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
    .with_static_gas(GAS_FOR_BURN_CALL)
    .burn(
        env::current_account_id(),
        mint_amount,
        relayer_account_id,
        U128(0),
    )
    .detach();   // ← result is never observed
```

`.detach()` means no callback is registered. If the `burn()` cross-contract call fails for any reason (e.g., gas exhaustion with only `GAS_FOR_BURN_CALL = 5 TGas` allocated, a panic inside `burn`, or any runtime error), the failure is silently swallowed. The bridge has already removed the UTXO from `verified_deposit_utxo` (line 441), so the deposit is considered failed and cannot be retried. The nBTC tokens minted to the bridge account are never destroyed.

This is the direct NEAR analog of the ERC20 `transferFrom` unchecked return value: a token operation whose success or failure is never verified, leaving the system in an inconsistent state.

---

### Impact Explanation

- The nBTC total supply becomes inflated: tokens exist in the bridge's own balance that have no BTC backing.
- The bridge's internal accounting (`ft_total_supply`) diverges from the actual BTC held in custody.
- These orphaned tokens sit in the bridge balance and could be used in future internal operations (e.g., relayer fee payments via `internal_transfer_nbtc`, protocol fee withdrawals), effectively allowing value to be extracted from the bridge without corresponding BTC.
- At minimum, this is a permanent supply inflation event requiring operator intervention to diagnose and remediate — a stuck/broken bridge state.

**Matched allowed impact:** Medium — permanent burning below backed supply / stuck bridge state requiring operator intervention.

---

### Likelihood Explanation

The trigger condition is:
1. A relayer calls `safe_verify_deposit` for a recipient account that is not registered on NEAR (a realistic scenario, since `safe_verify_deposit` is designed for Omni Bridge integrations where account registration is not guaranteed).
2. The detached `burn()` call fails — most plausibly due to the very tight `GAS_FOR_BURN_CALL = 5 TGas` allocation being insufficient for the burn execution plus any cross-contract overhead, or due to a transient runtime error.

Step 1 is reachable by any public relayer submitting a valid BTC proof for an unregistered recipient. Step 2 depends on gas conditions but is not implausible given the minimal gas budget. No privileged access is required.

---

### Recommendation

Replace the detached burn call with a chained callback that verifies success and handles failure:

```rust
ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
    .with_static_gas(GAS_FOR_BURN_CALL)
    .burn(
        env::current_account_id(),
        mint_amount,
        relayer_account_id,
        U128(0),
    )
    .then(
        Self::ext(env::current_account_id())
            .with_static_gas(GAS_FOR_SAFE_MINT_BURN_CALLBACK)
            .safe_mint_burn_callback(mint_amount),
    );
```

In `safe_mint_burn_callback`, if `is_promise_success()` is false, record the orphaned amount in `lost_found` or a dedicated recovery map so an operator can retry the burn. This mirrors the pattern already used correctly in `transfer_nbtc_callback` (`contracts/satoshi-bridge/src/token_transfer.rs` lines 54–75).

---

### Proof of Concept

1. Alice deposits BTC to a bridge address derived from a `DepositMsg` where `recipient_id = "alice.near"` (not registered on NEAR).
2. A relayer calls `safe_verify_deposit` with a valid Merkle proof.
3. The bridge calls `safe_mint("alice.near", amount, None)` on nBTC.
4. Inside `safe_mint`: `internal_deposit(&bridge_id, amount)` executes — nBTC tokens now exist in bridge balance. Then `accounts.get(&"alice.near")` returns `None`, so `safe_mint` returns `U128(0)`.
5. `safe_mint_callback` receives `is_refund_required() = true`, removes the UTXO from `verified_deposit_utxo`, and fires `burn(...).detach()` with 5 TGas.
6. The burn call fails (e.g., gas exhaustion). No callback exists to detect this.
7. Result: `amount` nBTC tokens remain in the bridge's balance with no BTC backing. `ft_total_supply()` is permanently inflated by `amount`. The UTXO is gone from the deposit set and cannot be reprocessed. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L438-456)
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
        }
```

**File:** contracts/nbtc/src/lib.rs (L112-116)
```rust
        self.token.internal_deposit(&self.bridge_id, amount.into());

        if self.token.accounts.get(&account_id).is_none() {
            return PromiseOrValue::Value(U128(0));
        }
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L6-6)
```rust
pub const GAS_FOR_BURN_CALL: Gas = Gas::from_tgas(5);
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
