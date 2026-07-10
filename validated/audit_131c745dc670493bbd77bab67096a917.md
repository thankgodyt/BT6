### Title
Full `env::attached_deposit()` Forwarded to MPC `sign()` Call Without Refund - (File: contracts/satoshi-bridge/src/chain_signature.rs)

### Summary

The `sign_promise` helper unconditionally forwards the caller's entire `env::attached_deposit()` to the external MPC chain-signatures `sign()` call. Because the MPC contract only consumes a fixed signing fee and does not refund the surplus, any NEAR attached above that fee is permanently transferred to the MPC contract and lost to the caller.

### Finding Description

`sign_promise` is the single path through which every signing request reaches the MPC contract:

```rust
// contracts/satoshi-bridge/src/chain_signature.rs  lines 62-68
pub fn sign_promise(&self, request: SignRequest) -> Promise {
    let config = self.internal_config();
    ext_chain_signatures::ext(config.chain_signatures_account_id.clone())
        .with_static_gas(GAS_FOR_SIGN_CALL)
        .with_attached_deposit(env::attached_deposit())   // ← full deposit forwarded
        .sign(request)
}
``` [1](#0-0) 

`sign_promise` is invoked by `internal_sign_btc_transaction`, which is itself called from the public, `#[payable]` entry point `sign_btc_transaction`:

```rust
// contracts/satoshi-bridge/src/api/chain_signatures.rs  lines 19-43
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn sign_btc_transaction(
    &mut self,
    btc_pending_sign_id: String,
    sign_index: usize,
    key_version: u32,
) -> PromiseOrValue<bool> { ... }
``` [2](#0-1) 

The downstream callback `sign_btc_transaction_callback` is `#[private]` and only processes the signature result; it contains no logic to refund any portion of the attached deposit to the original caller: [3](#0-2) 

The NEAR chain-signatures MPC contract's `sign()` function requires a fixed deposit to cover the signing fee. Any NEAR attached beyond that fixed amount is accepted by the MPC contract and never returned. Because `sign_promise` passes `env::attached_deposit()` verbatim — with no cap, no excess calculation, and no refund path — every yoctoNEAR above the required signing fee is permanently transferred to the MPC contract.

This is structurally identical to the Optimism finding: in that case the `cost` parameter was forwarded as `msg.value` to `sendMessage()` where it was unused; here the full `attached_deposit` is forwarded to `sign()` where only a fixed portion is consumed.

### Impact Explanation

Any caller of `sign_btc_transaction` who attaches more NEAR than the MPC contract's exact signing fee loses the surplus permanently. The surplus accumulates in the MPC chain-signatures contract with no recovery path from the bridge. This is a direct, irreversible loss of user funds on every over-funded signing call.

This matches the **Medium** allowed impact: "Harmful smart-contract behavior without direct funds theft, including … broken callback rollback, or stuck bridge state requiring operator intervention" — specifically the pattern of user funds being permanently transferred to an external contract where they serve no purpose and cannot be recovered.

### Likelihood Explanation

`sign_btc_transaction` is a public, unpermissioned, `#[payable]` function. Any NEAR account — including the withdrawal initiator or any relayer — can call it. The exact signing fee required by the MPC contract is not documented or enforced anywhere in the bridge contract, so callers routinely attach a safety margin. Every such call with a margin loses the excess. The function is called once per UTXO input per withdrawal, so multi-input withdrawals multiply the loss.

### Recommendation

Replace the unconditional `with_attached_deposit(env::attached_deposit())` with a fixed, protocol-defined signing deposit constant (e.g., `NearToken::from_yoctonear(SIGN_DEPOSIT)`), and refund any surplus to `env::predecessor_account_id()` before or after the cross-contract call. Alternatively, make `sign_btc_transaction` non-payable if the signing fee is already covered by the contract's own balance.

### Proof of Concept

1. A withdrawal is initiated via `ft_transfer_call` → `ft_on_transfer` → `create_btc_pending_info`, creating a `BTCPendingInfo` with `PendingInfoStage::PendingSign`.
2. A caller invokes `sign_btc_transaction("pending_id", 0, 0)` attaching 1 NEAR (a common safety margin over the ~0.25 NEAR signing fee).
3. `internal_sign_btc_transaction` calls `sign_promise`, which executes:
   ```
   ext_chain_signatures::ext(...).with_attached_deposit(1_000_000_000_000_000_000_000_000 yN).sign(request)
   ```
4. The MPC contract consumes its fixed signing fee (~0.25 NEAR) and retains the remaining ~0.75 NEAR.
5. `sign_btc_transaction_callback` fires, records the signature, and returns — no refund is issued.
6. The caller has permanently lost ~0.75 NEAR per signing call, with no recovery mechanism in the bridge.

### Citations

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L62-68)
```rust
    pub fn sign_promise(&self, request: SignRequest) -> Promise {
        let config = self.internal_config();
        ext_chain_signatures::ext(config.chain_signatures_account_id.clone())
            .with_static_gas(GAS_FOR_SIGN_CALL)
            .with_attached_deposit(env::attached_deposit())
            .sign(request)
    }
```

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
