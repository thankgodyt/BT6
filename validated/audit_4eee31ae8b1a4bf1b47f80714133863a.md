### Title
Detached Burn in `safe_mint_callback` Removes UTXO Replay-Protection Before Confirming Token Destruction, Enabling Double-Minting - (File: `contracts/satoshi-bridge/src/btc_light_client/deposit.rs`)

### Summary

In `safe_mint_callback`, when the `safe_mint` cross-contract call is deemed a failure, the contract removes the UTXO from `verified_deposit_utxo` (the sole replay-protection guard) and then fires a `burn` call with `.detach()`. Because the burn result is never checked, a silent burn failure leaves tokens minted while the UTXO is no longer protected, allowing the same UTXO to be re-submitted for deposit and minting a second time.

### Finding Description

The safe-deposit flow (`verify_deposit_v2` with `safe_deposit = Some(..)`) proceeds as follows:

1. `verify_safe_deposit_callback` inserts the UTXO into `verified_deposit_utxo` (replay guard) and calls `safe_mint` on the nbtc contract.
2. `safe_mint_callback` is invoked with the result.

In the failure branch of `safe_mint_callback`:

```rust
// contracts/satoshi-bridge/src/btc_light_client/deposit.rs  lines 438-455
} else {
    self.data_mut()
        .verified_deposit_utxo
        .remove(&pending_utxo_info.utxo_storage_key);   // ← replay guard removed

    ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
        .with_static_gas(GAS_FOR_BURN_CALL)
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

The UTXO is unconditionally removed from `verified_deposit_utxo` **before** the burn is confirmed. If the detached `burn` call fails for any reason (gas exhaustion, nbtc contract panic, insufficient bridge balance, contract upgrade), the tokens remain in existence while the UTXO is no longer in the replay-protection set. A subsequent call to `verify_deposit_v2` (standard or safe path) for the same UTXO will pass the `insert` check at line 402 and mint a second batch of tokens against the same on-chain BTC output.

This is the direct analog of the reported `balances[sender_] = _request.amount` overwrite: instead of a balance field being clobbered, the accounting invariant "every minted token is backed by exactly one entry in `verified_deposit_utxo`" is broken by removing the guard entry without atomically confirming the corresponding token destruction.

### Impact Explanation

If the detached burn fails:

- Tokens minted in the first deposit remain live (not burned).
- The UTXO is no longer in `verified_deposit_utxo`.
- A relayer (or the original depositor) can re-submit the same `tx_bytes` / `vout` proof to `verify_deposit_v2`, which will pass the `insert` guard and mint a second batch of nBTC.
- Net result: two batches of nBTC backed by a single BTC UTXO — unauthorized minting, breaking the 1:1 peg.

This matches **Critical — Unauthorized minting of nBTC**.

### Likelihood Explanation

The burn can fail in several realistic scenarios:

- **Gas exhaustion**: `GAS_FOR_BURN_CALL` is a static allocation; if the nbtc `burn` function's gas cost grows (e.g., after a contract upgrade), the call silently fails.
- **Bridge nbtc balance mismatch**: In the failure path the tokens may reside with the recipient (if `ft_on_transfer` consumed them before panicking), leaving the bridge with zero nbtc balance to burn.
- **nbtc contract paused or upgraded**: Any transient unavailability of the nbtc contract causes the detached call to fail silently.

An unprivileged depositor can deliberately trigger the failure branch by deploying a receiver contract whose `ft_on_transfer` panics or returns an unexpected value, then waiting for a window in which the burn fails. The entry path (`verify_deposit_v2`) is fully public.

### Recommendation

Remove the UTXO from `verified_deposit_utxo` **only inside a callback that confirms the burn succeeded**, not before. The burn should be chained (not detached) and the UTXO removal should be conditional on the burn callback returning success. If the burn fails, the UTXO must remain in `verified_deposit_utxo` to prevent replay, and the stuck tokens should be handled via an operator-accessible recovery path.

### Proof of Concept

1. Attacker deploys a NEAR contract `evil_receiver` whose `ft_on_transfer` always panics.
2. Attacker sends BTC to the deposit address derived from `DepositMsg { recipient_id: evil_receiver, safe_deposit: Some(..) }`.
3. Relayer calls `verify_deposit_v2` → `verify_safe_deposit_callback` inserts UTXO into `verified_deposit_utxo` and calls `safe_mint(evil_receiver, amount, ...)`.
4. `evil_receiver.ft_on_transfer` panics → `safe_mint` returns `U128(0)` → `is_refund_required()` returns `true` → `is_success = false`.
5. `safe_mint_callback` removes the UTXO from `verified_deposit_utxo` and fires a detached `burn`. If the bridge's nbtc balance is zero at this moment (tokens are stuck in the failed transfer), the burn fails silently.
6. UTXO is no longer in `verified_deposit_utxo`; tokens from step 3 remain minted (or are recoverable by the attacker from the nbtc contract's lost-and-found).
7. Relayer (or attacker) re-submits the same proof to `verify_deposit_v2` (standard path). The `insert` check at line 372 succeeds (UTXO not present), and a second `mint_amount` of nBTC is issued to any recipient the attacker chooses.
8. Attacker holds double the nBTC backed by a single BTC UTXO. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L387-419)
```rust
    pub fn verify_safe_deposit_callback(
        &mut self,
        recipient_id: AccountId,
        mint_amount: U128,
        msg: String,
        pending_utxo_info: PendingUTXOInfo,
    ) -> PromiseOrValue<bool> {
        let result_bytes = env::promise_result_checked(0, MAX_BOOL_RESULT)
            .expect("Call verify_transaction_inclusion failed");
        let is_valid = serde_json::from_slice::<bool>(&result_bytes)
            .expect("verify_transaction_inclusion return not bool");
        require!(is_valid, "verify_transaction_inclusion return false");
        require!(
            self.data_mut()
                .verified_deposit_utxo
                .insert(pending_utxo_info.utxo_storage_key.clone()),
            "Already deposit utxo"
        );

        let msg = (!msg.is_empty())
            .then(|| inject_utxo_id_in_msg(msg, &pending_utxo_info.utxo_storage_key));

        ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
            .with_static_gas(GAS_FOR_MINT_CALL)
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .safe_mint(recipient_id.clone(), mint_amount, msg)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_MINT_CALL_BACK)
                    .safe_mint_callback(recipient_id.clone(), mint_amount, pending_utxo_info),
            )
            .into()
    }
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
