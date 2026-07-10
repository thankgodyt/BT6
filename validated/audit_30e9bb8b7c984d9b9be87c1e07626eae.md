### Title
Detached `burn()` After UTXO De-registration in `safe_mint_callback` Enables nBTC Double-Mint - (File: contracts/satoshi-bridge/src/btc_light_client/deposit.rs)

---

### Summary

In `safe_mint_callback`, when a safe deposit is determined to have failed (`is_refund_required()` returns `true`), the bridge removes the UTXO from `verified_deposit_utxo` and then fires a `burn()` cross-contract call with `.detach()`. Because the call is detached, its failure is never observed or rolled back. If `burn()` fails for any reason, the minted nBTC tokens remain in the bridge's account while the UTXO is no longer protected by `verified_deposit_utxo`, leaving the same BTC UTXO open for re-submission via `verify_deposit`, which would mint a second batch of nBTC against the same on-chain BTC — a double-mint.

---

### Finding Description

`safe_mint_callback` in `contracts/satoshi-bridge/src/btc_light_client/deposit.rs` handles the result of the `safe_mint` → `ft_transfer_call` promise chain. When `is_refund_required()` returns `true` (i.e., `safe_mint` returned `U128(0)`, meaning the receiver's `ft_on_transfer` refunded all tokens back to the bridge), the callback executes the following sequence:

```rust
// Step 1 — UTXO de-registered FIRST
self.data_mut()
    .verified_deposit_utxo
    .remove(&pending_utxo_info.utxo_storage_key);   // line 439-441

// Step 2 — burn is fire-and-forget
ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
    .with_static_gas(GAS_FOR_BURN_CALL)
    .burn(env::current_account_id(), mint_amount, relayer_account_id, U128(0))
    .detach();                                        // line 443-451

// Step 3 — NEAR refund is also fire-and-forget
Promise::new(env::signer_account_id())
    .transfer(self.required_balance_for_safe_deposit())
    .detach();                                        // line 453-455
```

The ordering is critical: the UTXO is removed from `verified_deposit_utxo` **before** the `burn()` is scheduled, and the `burn()` result is never awaited. If `burn()` fails (e.g., the bridge's nBTC balance is transiently insufficient due to a concurrent withdrawal, or `GAS_FOR_BURN_CALL` is exhausted), the nBTC tokens remain in the bridge's account and the UTXO is permanently absent from `verified_deposit_utxo`.

The double-spend path then becomes:

1. Relayer calls `safe_verify_deposit` → `verify_safe_deposit_callback` inserts the UTXO into `verified_deposit_utxo` and calls `safe_mint`.
2. `safe_mint` mints `mint_amount` nBTC to the bridge, then calls `ft_transfer_call` to the OmniBridge receiver.
3. The receiver's `ft_on_transfer` returns the full amount (refund), so `safe_mint` returns `U128(0)`.
4. `safe_mint_callback` fires: UTXO removed from `verified_deposit_utxo`, `burn()` detached.
5. `burn()` fails silently — `mint_amount` nBTC remain in bridge account; UTXO is unprotected.
6. Any relayer now calls `verify_deposit` with the same UTXO. `verify_deposit_callback` calls `verified_deposit_utxo.insert(...)` — succeeds because the UTXO was removed in step 4.
7. `mint(recipient, mint_amount, ...)` is called, minting a second `mint_amount` nBTC.

Total nBTC supply inflated by `mint_amount` with no additional BTC backing.

The secondary detached call — `Promise::new(env::signer_account_id()).transfer(...).detach()` — is the direct structural analog of the `.transfer()` pattern flagged in the external report: a NEAR-token transfer with no callback, so if the signer account is deleted or the bridge has insufficient NEAR balance, the relayer's storage deposit is permanently lost with no recovery path.

---

### Impact Explanation

**Primary (Critical):** If `burn()` fails silently, the same BTC UTXO can be re-submitted to `verify_deposit`, minting a second batch of nBTC. This is unauthorized minting — nBTC supply exceeds backed BTC supply by `mint_amount`.

**Secondary (Medium):** The detached NEAR `transfer()` to the relayer has no failure callback. If it fails, the relayer's attached NEAR storage deposit is permanently lost with no operator recovery path.

---

### Likelihood Explanation

The `burn()` failure requires the bridge's nBTC balance to be transiently below `mint_amount` at the moment the detached call executes, or for `GAS_FOR_BURN_CALL` to be insufficient. In a high-throughput environment with concurrent withdrawals, the bridge's nBTC balance can fluctuate. Additionally, if the nbtc contract is paused or upgraded between the scheduling and execution of the detached call, `burn()` will panic and the failure will go undetected. The NEAR transfer failure is more likely: if the relayer account is deleted between the callback and the transfer execution, the NEAR is lost.

---

### Recommendation

Replace both `.detach()` calls with awaited callbacks that roll back state on failure:

1. For `burn()`: chain a callback that re-inserts the UTXO into `verified_deposit_utxo` if the burn fails, preventing re-deposit.
2. For the NEAR `transfer()`: chain a callback that records the owed amount in a `lost_found`-style map (analogous to the existing `lost_found` pattern in `transfer_nbtc_callback`) so the relayer can reclaim it later.

The state mutation (UTXO removal) must only become permanent after the burn is confirmed successful.

---

### Proof of Concept

**Trigger condition for `burn()` failure path:**

```
safe_verify_deposit(deposit_msg, tx_bytes, vout, proof)
  → verify_safe_deposit_callback: UTXO inserted into verified_deposit_utxo
  → safe_mint(recipient, mint_amount, msg)
      → ft_transfer_call(recipient, mint_amount, msg)
          → ft_on_transfer returns mint_amount  ← receiver rejects tokens
      → safe_mint returns U128(0)
  → safe_mint_callback:
      is_refund_required() == true → is_success = false
      verified_deposit_utxo.remove(utxo_key)   ← UTXO unprotected
      burn(...).detach()                        ← fails silently (e.g., gas exhaustion)
      transfer(...).detach()                    ← fails silently

verify_deposit(same deposit_msg, same tx_bytes, vout, proof)
  → verify_deposit_callback:
      verified_deposit_utxo.insert(utxo_key)   ← succeeds, UTXO was removed
      mint(recipient, mint_amount, ...)         ← second mint for same BTC UTXO
```

Relevant code locations: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L354-384)
```rust
    #[private]
    pub fn verify_deposit_callback(
        &mut self,
        recipient_id: AccountId,
        mint_amount: U128,
        protocol_fee: U128,
        relayer_fee: U128,
        pending_utxo_info: PendingUTXOInfo,
        post_actions: Option<Vec<PostAction>>,
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
        self.internal_mint_promise(
            recipient_id,
            mint_amount,
            protocol_fee,
            relayer_fee,
            pending_utxo_info,
            post_actions,
        )
        .into()
    }
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L386-419)
```rust
    #[private]
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

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L474-488)
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
```
