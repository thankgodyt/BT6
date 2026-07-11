### Title
Silent Failure in `sign_btc_transaction_callback` — No Event Emitted on MPC Signing Failure - (File: contracts/satoshi-bridge/src/chain_signature.rs)

### Summary
When the MPC chain-signature call fails, `sign_btc_transaction_callback` returns `false` silently with no on-chain event emitted. Off-chain systems monitoring bridge events receive no signal that signing failed, leaving the withdrawal in a `PendingSign` state with no observable on-chain notification.

### Finding Description
In `sign_btc_transaction_callback`, the success branch emits both `Event::BtcInputSignature` and (when all inputs are signed) `Event::SignedBtcTransaction`. However, the failure branch — entered when `env::promise_result_checked` returns `Err` — simply returns `false` with no state update and no event:

```rust
// contracts/satoshi-bridge/src/chain_signature.rs
pub fn sign_btc_transaction_callback(
    &mut self,
    account_id: AccountId,
    btc_pending_sign_id: String,
    sign_index: usize,
) -> bool {
    if let Ok(result_bytes) = env::promise_result_checked(0, MAX_SIGNATURE_RESULT) {
        // ... emits BtcInputSignature, optionally SignedBtcTransaction
        true
    } else {
        false   // ← no event, no state change, silent
    }
}
```

This is the direct analog of the external report: a condition check fails, the intended action is not performed, and the caller receives no on-chain notice beyond the raw return value.

The `btc_pending_info` entry remains in `PendingInfoStage::PendingSign`. Because no event is emitted, any off-chain relayer or monitoring system that drives retry logic by watching bridge events has no signal to act on. The withdrawal is silently stalled. [1](#0-0) 

Compare with the success path which always emits `Event::BtcInputSignature`: [2](#0-1) 

And the project's own stated invariant — "emit events AFTER all state mutations complete" — which the failure branch violates by emitting nothing: [3](#0-2) 

### Impact Explanation
When MPC signing fails (e.g., transient network error, key-version mismatch, gas exhaustion in the MPC call), the withdrawal is left in `PendingSign` with no on-chain event. Off-chain systems that rely on events to schedule retries or alert operators have no trigger. The user's nBTC tokens are already held by the bridge (transferred in step 1 of the withdrawal flow) and cannot be recovered until signing eventually succeeds or an operator manually intervenes. This constitutes a stuck bridge state requiring operator intervention. [4](#0-3) 

### Likelihood Explanation
MPC signing failures are a realistic operational event (transient network issues, gas limits, key-version changes). The `sign_btc_transaction` entry point is publicly callable by any user, so any withdrawal attempt can reach this callback. The silent failure is guaranteed to occur whenever the MPC call does not return a valid signature. [5](#0-4) 

### Recommendation
Emit a dedicated failure event in the `else` branch of `sign_btc_transaction_callback`, analogous to how `mint_callback` and `transfer_nbtc_callback` unconditionally emit their outcome events:

```rust
} else {
    Event::BtcInputSignatureFailed {
        account_id: &account_id,
        btc_pending_id: &btc_pending_sign_id,
        sign_index,
    }
    .emit();
    false
}
```

This mirrors the fix described in the external report (adding an `else` branch with an event emission) and aligns with the project's own security invariant of emitting events after all state mutations. [6](#0-5) 

### Proof of Concept
1. User calls `nbtc.ft_transfer_call(bridge, amount, WithdrawMsg{...})`.
2. Bridge receives tokens, calls `sign_btc_transaction(btc_pending_sign_id, 0, key_version)`.
3. Bridge calls MPC `sign(...)`. MPC call fails (returns error / panics internally).
4. `sign_btc_transaction_callback` is invoked; `env::promise_result_checked` returns `Err`.
5. Callback returns `false`. **No event is emitted.**
6. `btc_pending_info` remains in `PendingSign` state.
7. Off-chain relayer watching bridge events sees nothing — no retry is triggered.
8. User's nBTC remains locked in the bridge with no on-chain observable signal of the failure. [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L134-213)
```rust
    #[private]
    pub fn sign_btc_transaction_callback(
        &mut self,
        account_id: AccountId,
        btc_pending_sign_id: String,
        sign_index: usize,
    ) -> bool {
        if let Ok(result_bytes) = env::promise_result_checked(0, MAX_SIGNATURE_RESULT) {
            let signature = serde_json::from_slice::<SignatureResponse>(&result_bytes)
                .expect("Invalid signature");

            let public_key = self
                .generate_btc_public_key(
                    &self
                        .internal_unwrap_btc_pending_info(&btc_pending_sign_id)
                        .vutxos[sign_index]
                        .get_path(),
                )
                .inner;
            let btc_pending_info = self.internal_unwrap_mut_btc_pending_info(&btc_pending_sign_id);
            require!(
                btc_pending_info.signatures[sign_index].is_none(),
                "Already signed"
            );
            btc_pending_info.signatures[sign_index] = Some(signature.clone());
            btc_pending_info.last_sign_time_sec = nano_to_sec(env::block_timestamp());
            Event::BtcInputSignature {
                account_id: &account_id,
                btc_pending_id: &btc_pending_sign_id,
                sign_index,
                signature: &signature,
            }
            .emit();
            let mut psbt = btc_pending_info.get_psbt();
            psbt.save_signature(sign_index, signature, public_key);

            btc_pending_info.psbt_hex = psbt.serialize();
            if btc_pending_info.is_all_signed() {
                let tx_bytes_with_sign = psbt.extract_tx_bytes_with_sign();

                // For ZCash chains, use base64 encoding to save space (1.33x vs 2x overhead for hex)
                // ZCash transactions with Orchard bundles are larger and benefit from compact encoding
                // For Bitcoin chains, keep hex encoding for backward compatibility

                #[cfg(feature = "zcash")]
                let tx_bytes_base64 = {
                    use near_sdk::base64::{engine::general_purpose::STANDARD, Engine};
                    STANDARD.encode(&tx_bytes_with_sign)
                };

                Event::SignedBtcTransaction {
                    account_id: &account_id,
                    tx_id: btc_pending_sign_id.clone(),
                    #[cfg(not(feature = "zcash"))]
                    tx_bytes: &tx_bytes_with_sign,
                    #[cfg(feature = "zcash")]
                    tx_bytes_base64,
                }
                .emit();

                btc_pending_info.tx_bytes_with_sign = Some(tx_bytes_with_sign);
                btc_pending_info.to_pending_verify_stage();

                let is_original_tx = btc_pending_info.get_original_tx_id().is_none();
                let account = self.internal_unwrap_mut_account(&account_id);
                require!(
                    account.btc_pending_sign_ids.remove(&btc_pending_sign_id),
                    "Internal error"
                );
                if is_original_tx {
                    account
                        .btc_pending_verify_list
                        .insert(btc_pending_sign_id.clone());
                }
            }
            true
        } else {
            false
        }
    }
```

**File:** CLAUDE.md (L45-55)
```markdown
**Withdraw (nBTC → BTC)**
```
1. User: nbtc.ft_transfer(bridge, amount, WithdrawMsg)
   → Tokens TRANSFERRED to bridge (not burned yet!)
2. nBTC: bridge.ft_on_transfer(user, amount, msg) → Bridge returns 0 (keeps tokens)
3. Bridge creates BTC tx, Chain Signatures signs
4. Tx broadcast to Bitcoin network
5. Relayer: bridge.verify_withdraw(tx_proof)
6. Bridge verifies → calls nbtc.burn(user, amount, relayer, fee)
   → Burns from bridge balance (tokens already there!)
```
```

**File:** CLAUDE.md (L73-75)
```markdown
- Mutate state (mark UTXO used, update balances) BEFORE cross-contract calls
- Create and emit events AFTER all state mutations complete
- **Cross-contract calls are NOT atomic:** Each callback is a separate transaction - must manually rollback state in callback if external call fails
```

**File:** contracts/satoshi-bridge/src/api/chain_signatures.rs (L19-43)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_btc_transaction(
        &mut self,
        btc_pending_sign_id: String,
        sign_index: usize,
        key_version: u32,
    ) -> PromiseOrValue<bool> {
        let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);
        btc_pending_info.assert_pending_sign();
        if let Some(original_tx_id) = btc_pending_info.get_original_tx_id() {
            if !self.check_btc_pending_info_exists(original_tx_id) {
                require!(
                    self.internal_unwrap_mut_account(&btc_pending_info.account_id.clone())
                        .btc_pending_sign_ids
                        .remove(&btc_pending_sign_id),
                    "Internal error"
                );
                self.internal_remove_btc_pending_info(&btc_pending_sign_id);
                return PromiseOrValue::Value(true);
            }
        }
        self.internal_sign_btc_transaction(btc_pending_sign_id, sign_index, key_version)
            .into()
    }
```

**File:** contracts/satoshi-bridge/src/nbtc/mint.rs (L69-83)
```rust
        } else {
            self.data_mut()
                .verified_deposit_utxo
                .remove(&pending_utxo_info.utxo_storage_key);
        }
        Event::VerifyDepositDetails {
            recipient_id: &recipient_id,
            mint_amount,
            protocol_fee,
            relayer_account_id: env::signer_account_id(),
            relayer_fee,
            success: is_success,
        }
        .emit();
        is_success
```
