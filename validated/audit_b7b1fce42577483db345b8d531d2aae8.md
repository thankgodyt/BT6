### Title
Excess NEAR Attached to `sign_btc_transaction` Is Refunded to the Bridge Contract Instead of the Caller — (File: `contracts/satoshi-bridge/src/chain_signature.rs`)

---

### Summary

`sign_btc_transaction` is a `#[payable]` function that forwards the caller's entire `env::attached_deposit()` to the NEAR Chain Signatures MPC contract via `sign_promise`. If the MPC contract refunds any excess deposit, that refund is returned to the bridge contract (`env::current_account_id()`), not to the original caller (`env::predecessor_account_id()`). The excess NEAR is permanently stuck in the bridge contract with no user-accessible recovery path.

---

### Finding Description

In `sign_promise` (chain_signature.rs):

```rust
pub fn sign_promise(&self, request: SignRequest) -> Promise {
    let config = self.internal_config();
    ext_chain_signatures::ext(config.chain_signatures_account_id.clone())
        .with_static_gas(GAS_FOR_SIGN_CALL)
        .with_attached_deposit(env::attached_deposit())   // ← entire caller deposit forwarded
        .sign(request)
}
``` [1](#0-0) 

The full `env::attached_deposit()` captured at the `sign_btc_transaction` call site is blindly forwarded to the MPC `sign` call. On NEAR, when a cross-contract call completes (success or failure), any unused portion of the attached deposit is refunded to the **calling contract** (`env::current_account_id()` = the bridge), not to the original transaction signer (`env::predecessor_account_id()` = the user). There is no subsequent promise or callback that transfers this refund back to the user.

The public entry point is:

```rust
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn sign_btc_transaction(
    &mut self,
    btc_pending_sign_id: String,
    sign_index: usize,
    key_version: u32,
) -> PromiseOrValue<bool> { ... }
``` [2](#0-1) 

Any NEAR attached above the MPC contract's actual signing fee is silently absorbed by the bridge contract. The bridge has no function that allows a user to reclaim accidentally over-deposited NEAR (the `claim_lost_found` mechanism only covers nBTC, not NEAR). [3](#0-2) 

---

### Impact Explanation

A user who attaches more NEAR than the MPC signing fee requires permanently loses the excess. The NEAR accumulates in the bridge contract's balance with no user-accessible withdrawal path. This constitutes a permanent loss of user funds (NEAR tokens) triggered by a publicly reachable, unprivileged call path.

**Impact class**: Medium — harmful smart-contract behavior causing permanent loss of user-supplied NEAR without a direct BTC/nBTC theft.

---

### Likelihood Explanation

`sign_btc_transaction` is called by every user who initiates a withdrawal or refund signing step. The exact NEAR deposit required by the MPC `sign` function is not documented in the bridge interface, so users (and wallets) routinely over-attach to avoid rejection. Every such over-payment results in irrecoverable loss. Likelihood is **medium-high** given the function is on the critical withdrawal path and the required deposit amount is opaque to callers.

---

### Recommendation

After forwarding the deposit to the MPC contract, add a callback that computes the difference between `env::attached_deposit()` and the amount actually consumed, then transfers the remainder back to the original caller:

```rust
// capture predecessor before async boundary
let caller = env::predecessor_account_id();
self.sign_promise(request)
    .then(
        Self::ext(env::current_account_id())
            .refund_excess_deposit_callback(caller, env::attached_deposit())
    )
```

Alternatively, require callers to attach exactly the MPC fee (expose a `required_balance_for_sign()` view function) and reject calls that over-attach, mirroring the pattern used by `assert_one_yocto` elsewhere in the contract.

---

### Proof of Concept

1. User calls `sign_btc_transaction("pending_id", 0, 0)` attaching 1 NEAR (MPC fee is, say, 0.1 NEAR).
2. `internal_sign_btc_transaction` calls `sign_promise`, which executes:
   ```
   ext_chain_signatures::sign(...).with_attached_deposit(1 NEAR)
   ``` [4](#0-3) 
3. MPC contract consumes 0.1 NEAR and refunds 0.9 NEAR to the bridge contract (`env::current_account_id()`).
4. `sign_btc_transaction_callback` runs — it processes the signature but never transfers the 0.9 NEAR refund to the user. [5](#0-4) 
5. The 0.9 NEAR is permanently stuck in the bridge contract. The user has no function to recover it.

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

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L99-113)
```rust
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L449-460)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn claim_lost_found(&mut self) -> Promise {
        assert_one_yocto();
        let account_id = env::predecessor_account_id();
        let amount = self
            .data_mut()
            .lost_found
            .remove(&account_id)
            .expect("The account does not have lostfound");
        self.internal_transfer_nbtc(&account_id, amount)
    }
```
