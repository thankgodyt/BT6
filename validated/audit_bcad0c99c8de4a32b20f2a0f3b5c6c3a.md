### Title
No Minimum Fee Validation in `sign_btc_transaction` Causes Silent MPC Failure and Caller NEAR Loss - (File: contracts/satoshi-bridge/src/api/chain_signatures.rs)

### Summary

`sign_btc_transaction` is `#[payable]` and blindly forwards `env::attached_deposit()` to the NEAR Chain Signatures MPC `sign` call. There is no minimum-fee guard. When the MPC call fails due to insufficient attached NEAR, the callback silently returns `false` without refunding the caller, permanently crediting the lost NEAR to the bridge contract's balance. The withdrawal or refund transaction remains stuck in `PendingSign` state.

### Finding Description

`sign_btc_transaction` in `contracts/satoshi-bridge/src/api/chain_signatures.rs` is declared `#[payable]` and delegates immediately to `internal_sign_btc_transaction`, which calls `sign_promise`:

```rust
pub fn sign_promise(&self, request: SignRequest) -> Promise {
    let config = self.internal_config();
    ext_chain_signatures::ext(config.chain_signatures_account_id.clone())
        .with_static_gas(GAS_FOR_SIGN_CALL)
        .with_attached_deposit(env::attached_deposit())   // ← forwarded verbatim
        .sign(request)
}
``` [1](#0-0) 

The NEAR Chain Signatures MPC contract requires a non-trivial NEAR deposit to cover the signing fee. No lower-bound check exists anywhere between the public entry point and the cross-contract call.

When the MPC `sign` call fails (e.g., zero or sub-minimum NEAR attached), the callback branch is:

```rust
} else {
    false
}
``` [2](#0-1) 

In NEAR Protocol, a failed cross-contract call refunds the attached deposit to the **calling contract** (the bridge), not to the original transaction signer. The callback contains no logic to forward that refund back to the caller. The NEAR is silently absorbed into the bridge's account balance, and the `BtcPendingInfo` remains in `PendingSign` state indefinitely. [3](#0-2) 

### Impact Explanation

Two concrete harms result:

1. **Loss of caller NEAR**: Any account that calls `sign_btc_transaction` with an insufficient deposit loses that NEAR permanently to the bridge contract. There is no refund path in the callback.

2. **Stuck withdrawal/refund state**: A withdrawal or refund `BtcPendingInfo` that never receives a successful MPC signature stays in `PendingSign` indefinitely. The user's nBTC has already been transferred to the bridge via `ft_transfer_call`; they cannot recover it until a successful signing occurs. For refund flows, the user's BTC is also locked on-chain. This matches the **Medium** impact class: attacker-triggered temporary locking of bridged funds / stuck bridge state requiring operator intervention.

### Likelihood Explanation

`sign_btc_transaction` is a public, permissionless function (only paused by DAO). Any bridge user or relayer who calls it without knowing the exact MPC fee triggers the bug. The NEAR Chain Signatures MPC fee is not documented in the bridge, and no query function exists to estimate it, making accidental under-payment highly likely. A malicious actor could also deliberately call it with 1 yoctoNEAR to grief a pending withdrawal.

### Recommendation

1. **Enforce a minimum attached deposit**: Add a `require!` guard at the top of `sign_btc_transaction` (or inside `sign_promise`) that checks `env::attached_deposit() >= MIN_MPC_SIGN_FEE`, where `MIN_MPC_SIGN_FEE` is a configurable constant or stored in `Config`.

2. **Refund on MPC failure**: In `sign_btc_transaction_callback`, when the promise result is an error, refund the originally attached deposit to `env::predecessor_account_id()` via `Promise::new(...).transfer(...)`.

3. **Expose a fee-estimation view**: Add a view function that returns the current minimum MPC signing fee so callers can attach the correct amount.

### Proof of Concept

```
1. Alice initiates a withdrawal: ft_transfer_call(bridge, amount, WithdrawMsg)
   → Bridge creates BtcPendingInfo { state: PendingSign, ... }
   → Alice's nBTC is now held by the bridge

2. Bob (or Alice) calls:
   sign_btc_transaction(btc_pending_sign_id, 0, 0)
   with attached_deposit = 1 yoctoNEAR

3. Bridge forwards 1 yoctoNEAR to chain-signatures.sign(request)
   → MPC contract panics: "Insufficient fee"
   → 1 yoctoNEAR is refunded to bridge contract balance

4. sign_btc_transaction_callback receives failed promise result
   → returns false, no refund to Bob, no state change

5. BtcPendingInfo remains in PendingSign state
   → Alice's withdrawal is stuck; her nBTC is locked in the bridge
   → Bob lost 1 yoctoNEAR (trivial here, but scales with realistic MPC fees)

6. No mechanism exists to estimate the correct fee or recover the lost NEAR
``` [4](#0-3) [5](#0-4)

### Citations

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L61-113)
```rust
impl Contract {
    pub fn sign_promise(&self, request: SignRequest) -> Promise {
        let config = self.internal_config();
        ext_chain_signatures::ext(config.chain_signatures_account_id.clone())
            .with_static_gas(GAS_FOR_SIGN_CALL)
            .with_attached_deposit(env::attached_deposit())
            .sign(request)
    }

    pub fn sync_chain_signatures_root_public_key_promise(&mut self) -> Promise {
        ext_chain_signatures::ext(self.internal_config().chain_signatures_account_id.clone())
            .public_key(None)
            .then(Self::ext(env::current_account_id()).sync_root_public_key_callback())
    }

    pub fn internal_sign_btc_transaction(
        &mut self,
        btc_pending_sign_id: String,
        sign_index: usize,
        key_version: u32,
    ) -> Promise {
        let pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);

        let public_keys: Vec<_> = pending_info
            .vutxos
            .iter()
            .map(|vutxo| self.generate_btc_public_key(&vutxo.get_path()))
            .collect();

        let btc_pending_info = self.internal_unwrap_btc_pending_info(&btc_pending_sign_id);
        require!(
            btc_pending_info.signatures[sign_index].is_none(),
            "Already signed"
        );
        let payload = btc_pending_info
            .get_psbt()
            .get_hash_to_sign(sign_index, &public_keys);
        let path = btc_pending_info.vutxos[sign_index].get_path();
        self.sign_promise(SignRequest {
            payload,
            path,
            key_version,
        })
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_FOR_SIGN_BTC_TRANSACTION_CALL_BACK)
                .sign_btc_transaction_callback(
                    btc_pending_info.account_id.clone(),
                    btc_pending_sign_id,
                    sign_index,
                ),
        )
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
