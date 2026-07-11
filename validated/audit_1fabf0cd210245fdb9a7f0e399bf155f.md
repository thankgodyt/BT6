### Title
Hardcoded 5 Tgas Limit on Detached Burn Call Enables Silent Failure and Double-Minting of nBTC - (File: contracts/satoshi-bridge/src/nbtc/burn.rs)

### Summary
`GAS_FOR_BURN_CALL` is hardcoded to 5 Tgas and is used in a fire-and-forget (`.detach()`) burn call inside `safe_mint_callback`. If the burn fails due to insufficient gas, the minted nBTC tokens remain in the bridge contract's balance while the UTXO is simultaneously removed from `verified_deposit_utxo`. This allows the same BTC UTXO to be re-submitted via `verify_deposit`, minting a second batch of nBTC for the same underlying BTC — a double-mint.

### Finding Description
In `contracts/satoshi-bridge/src/nbtc/burn.rs`, the constant `GAS_FOR_BURN_CALL` is set to only 5 Tgas: [1](#0-0) 

This constant is reused in `safe_mint_callback` (in `contracts/satoshi-bridge/src/btc_light_client/deposit.rs`) for the recovery burn when `safe_mint` fails. Critically, this burn is issued with `.detach()` — there is no callback to detect or handle failure: [2](#0-1) 

Immediately before the detached burn, the UTXO is removed from `verified_deposit_utxo`: [3](#0-2) 

The `verify_deposit_callback` path enforces uniqueness by requiring `verified_deposit_utxo.insert(...)` to return `true` (i.e., the key was not already present): [4](#0-3) 

Because the UTXO was removed from `verified_deposit_utxo` in the failure branch of `safe_mint_callback`, a subsequent call to `verify_deposit` for the same UTXO will pass this uniqueness check and proceed to mint a second batch of nBTC.

The asymmetry between the mint gas allocation (90 Tgas) and the burn gas allocation (5 Tgas) is stark: [5](#0-4) [6](#0-5) 

If the nBTC contract's `burn` function requires more than 5 Tgas (e.g., due to storage operations, event emission, or future upgrades), the detached call will silently fail, leaving the bridge in an inconsistent state with no on-chain indication of the failure.

### Impact Explanation
**Critical.** A failed detached burn leaves nBTC tokens minted in the bridge contract's balance while the UTXO guard is removed. Any caller can then re-submit the same BTC deposit proof via `verify_deposit`, causing the bridge to mint a second batch of nBTC for the same UTXO. This constitutes unauthorized minting of nBTC tokens unbacked by BTC, directly violating the vault-and-mint invariant of the bridge.

### Likelihood Explanation
**Medium.** The 5 Tgas budget is extremely tight for a cross-contract call to a custom token contract. The nBTC `burn` function must at minimum deserialize arguments, update two storage entries (account balance and total supply), and serialize a return value. If the nBTC contract emits events or performs additional checks, 5 Tgas is plausibly insufficient. Furthermore, NEAR gas costs can shift across protocol upgrades (analogous to EIP-1884 on Ethereum), making a currently-passing budget unreliable over time. The trigger condition (a `safe_mint` receiver returning 0) is reachable by any user who deploys a receiver contract that rejects the transfer.

### Recommendation
1. Increase `GAS_FOR_BURN_CALL` to a value consistent with the nBTC contract's actual burn cost — at minimum align it with the gas used in the withdrawal burn path, which has a measured callback budget.
2. Remove `.detach()` from the burn call in `safe_mint_callback` and add a callback that, on burn failure, re-inserts the UTXO key into `verified_deposit_utxo` to prevent re-deposit.
3. Alternatively, do not remove the UTXO from `verified_deposit_utxo` until the burn callback confirms success.

### Proof of Concept
1. Attacker deploys a NEAR contract whose `ft_on_transfer` always returns `U128(0)` (unused tokens).
2. Attacker deposits BTC to the bridge address derived from a `DepositMsg` pointing to their NEAR account with a `safe_deposit` message targeting their malicious receiver.
3. Attacker calls `safe_verify_deposit` with a valid SPV proof. The bridge calls `safe_mint` on nBTC, which mints tokens and calls `ft_on_transfer` on the malicious receiver.
4. The malicious receiver returns `U128(0)`. `is_refund_required()` returns `true`.
5. `safe_mint_callback` executes the `else` branch: removes the UTXO from `verified_deposit_utxo`, then issues a detached `burn` with 5 Tgas that fails silently.
6. nBTC tokens (equal to the deposit amount) remain minted in the bridge contract's balance. The UTXO is no longer in `verified_deposit_utxo`.
7. Attacker (or any relayer) calls `verify_deposit` with the same BTC transaction proof and a standard `DepositMsg` pointing to the attacker's account.
8. `verify_deposit_callback` finds the UTXO absent from `verified_deposit_utxo`, inserts it, and calls `internal_mint_promise`, minting a second batch of nBTC to the attacker.
9. The attacker now holds nBTC tokens backed by a single BTC UTXO that was only deposited once — a net double-mint.

### Citations

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L6-8)
```rust
pub const GAS_FOR_BURN_CALL: Gas = Gas::from_tgas(5);
pub const GAS_FOR_WITHDRAW_BURN_CALL_BACK: Gas = Gas::from_tgas(20);
pub const GAS_FOR_ACTIVE_UTXO_MANAGEMENT_BURN_CALL_BACK: Gas = Gas::from_tgas(20);
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L369-373)
```rust
        require!(
            self.data_mut()
                .verified_deposit_utxo
                .insert(pending_utxo_info.utxo_storage_key.clone()),
            "Already deposit utxo"
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

**File:** contracts/satoshi-bridge/src/nbtc/mint.rs (L6-7)
```rust
pub const GAS_FOR_MINT_CALL: Gas = Gas::from_tgas(90);
pub const GAS_FOR_MINT_CALL_BACK: Gas = Gas::from_tgas(10);
```
