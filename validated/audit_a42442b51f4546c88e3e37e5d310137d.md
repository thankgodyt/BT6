### Title
Detached `burn()` Call in `safe_mint_callback` Has No Failure Handler, Permanently Locking nBTC in Bridge Balance — (File: `contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

### Summary

In `safe_mint_callback`, when the `safe_mint` cross-contract call fails (i.e., the downstream receiver returns all tokens), the bridge fires a `burn()` call on the nBTC contract using `.detach()` — with no callback and no retry mechanism. If that detached burn fails, the minted nBTC tokens remain permanently in the bridge's balance, inflating the nBTC supply beyond its BTC backing, with no on-chain recovery path.

### Finding Description

The `safe_verify_deposit` flow calls `safe_mint` on the nBTC contract, which first deposits `mint_amount` tokens into the bridge's own balance, then attempts to forward them to the recipient via `ft_transfer_call`. If the recipient's `ft_on_transfer` returns the full amount (refund), `ft_resolve_transfer` returns `0` (zero tokens used), and `safe_mint` resolves to `U128(0)`.

`safe_mint_callback` detects this via `is_refund_required()`: [1](#0-0) 

When `is_refund_required()` returns `true`, `is_success = false`, and the callback takes the failure branch: [2](#0-1) 

Two critical actions happen here:

1. The UTXO is removed from `verified_deposit_utxo` — permanently preventing re-verification of this deposit.
2. `burn()` is called with `.detach()` — **no callback, no failure handler, no retry mechanism**.

If the detached `burn()` call fails for any reason (gas exhaustion, nBTC contract panic, or insufficient bridge balance due to a concurrent withdrawal draining it between receipts), the `mint_amount` tokens deposited into the bridge's balance by `safe_mint` remain there permanently. The UTXO is already removed from `verified_deposit_utxo`, so the deposit cannot be re-triggered. There is no operator-callable retry function for this specific cleanup step.

The `burn()` function in the nBTC contract: [3](#0-2) 

It calls `internal_withdraw` on the bridge's balance. If the bridge's nBTC balance has been reduced below `mint_amount` by a concurrent withdrawal receipt executing between the `safe_mint_callback` receipt and the detached `burn()` receipt, `internal_withdraw` will panic and the burn will fail silently.

The gas budget allocated to the burn is only `GAS_FOR_BURN_CALL = Gas::from_tgas(5)`: [4](#0-3) 

This is the same constant reused from the withdrawal burn path, and while 5 TGas is normally sufficient, it is a tight budget that leaves no margin for unexpected storage growth or nBTC contract changes.

By contrast, the withdrawal burn path correctly handles failure by reverting the pending info stage: [5](#0-4) 

The `safe_mint_callback` failure branch has no equivalent rollback.

### Impact Explanation

If the detached `burn()` fails:
- `mint_amount` nBTC tokens remain in the bridge's balance permanently.
- The nBTC total supply is inflated beyond its BTC backing (unbacked nBTC exists on-chain).
- The deposit UTXO is removed from `verified_deposit_utxo` with no recovery path.
- No operator function exists to retry the cleanup burn for this specific case.

This matches **Medium — permanent burning below backed supply / stuck bridge state requiring operator intervention**.

### Likelihood Explanation

The `safe_verify_deposit` path is publicly callable by any relayer submitting a valid BTC proof. The failure branch is triggered whenever the downstream receiver's `ft_on_transfer` returns the full amount. The detached burn then fails if the bridge's nBTC balance is concurrently reduced below `mint_amount` by a withdrawal receipt executing in the same block, or if the nBTC contract panics for any reason. While individually unlikely, the combination is reachable without any privileged access.

### Recommendation

Replace the `.detach()` burn with a chained callback that handles failure — analogous to how `verify_withdraw_burn_callback` reverts state on burn failure. Specifically:

1. Remove `.detach()` from the `burn()` call in `safe_mint_callback`.
2. Add a `safe_mint_burn_callback` that checks `is_promise_success()`.
3. On burn failure, re-insert the UTXO key into `verified_deposit_utxo` and record the stuck amount in `lost_found` or a dedicated recovery map so an operator can retry.

### Proof of Concept

1. Relayer calls `safe_verify_deposit` with a valid BTC proof for a deposit to a receiver contract.
2. Bridge verifies proof → calls `safe_mint(recipient, amount, Some(msg))`.
3. `safe_mint` deposits `amount` nBTC to bridge balance, then calls `ft_transfer_call(recipient, amount, msg)`.
4. Recipient's `ft_on_transfer` returns `amount` (full refund). `ft_resolve_transfer` returns `0`. `safe_mint` resolves to `U128(0)`.
5. `safe_mint_callback` fires: `is_refund_required()` returns `true`, `is_success = false`.
6. UTXO removed from `verified_deposit_utxo`. `burn(bridge, amount).detach()` is fired.
7. A concurrent withdrawal receipt (submitted in the same block) drains the bridge's nBTC balance below `amount`.
8. The detached `burn()` receipt executes: `internal_withdraw` panics — burn fails silently.
9. `amount` nBTC tokens remain in bridge balance permanently. UTXO is gone from `verified_deposit_utxo`. No retry path exists. [6](#0-5)

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

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L6-6)
```rust
pub const GAS_FOR_BURN_CALL: Gas = Gas::from_tgas(5);
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L149-152)
```rust
        } else {
            self.internal_unwrap_mut_btc_pending_info(&tx_id)
                .to_pending_verify_stage();
        }
```
