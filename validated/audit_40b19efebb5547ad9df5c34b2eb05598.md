### Title
Excess NEAR Attached to `sign_btc_transaction` Is Permanently Lost — (File: `contracts/satoshi-bridge/src/chain_signature.rs`)

### Summary
The `sign_btc_transaction` function is `#[payable]` and forwards the caller's entire `env::attached_deposit()` to the chain signatures contract via `sign_promise`. There is no mechanism to query the exact fee required by chain signatures, and no refund of any excess NEAR is ever issued back to the caller. Any NEAR attached beyond the exact signing fee is permanently lost — either consumed by the chain signatures contract or, if chain signatures refunds excess to its caller (the bridge), it accumulates in the bridge contract with no user-accessible retrieval path.

### Finding Description
In `contracts/satoshi-bridge/src/chain_signature.rs`, `sign_promise` unconditionally forwards the full `env::attached_deposit()` to the external chain signatures contract:

```rust
pub fn sign_promise(&self, request: SignRequest) -> Promise {
    let config = self.internal_config();
    ext_chain_signatures::ext(config.chain_signatures_account_id.clone())
        .with_static_gas(GAS_FOR_SIGN_CALL)
        .with_attached_deposit(env::attached_deposit())   // ← entire deposit forwarded
        .sign(request)
}
``` [1](#0-0) 

This is called from `internal_sign_btc_transaction`, which is invoked by the public `#[payable]` entry point `sign_btc_transaction`:

```rust
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn sign_btc_transaction(
    &mut self,
    btc_pending_sign_id: String,
    sign_index: usize,
    key_version: u32,
) -> PromiseOrValue<bool> {
``` [2](#0-1) 

The bridge exposes no `required_balance_for_sign` view function (unlike `required_balance_for_request_refund` or `required_balance_for_execute_refund`), so callers have no on-chain way to determine the exact fee. The `sign_btc_transaction_callback` performs no refund of any excess NEAR returned by chain signatures: [3](#0-2) 

There is no `claim_excess` or similar mechanism in the bridge for NEAR that accumulates from over-payment.

### Impact Explanation
Any NEAR attached in excess of the chain signatures signing fee is permanently unrecoverable by the user. If the chain signatures contract refunds excess to its caller (the bridge contract), that NEAR silently accumulates in the bridge with no user-accessible withdrawal path. If chain signatures does not refund excess, the NEAR is consumed outright. Either outcome constitutes a direct financial loss for the caller. This matches the **Low** allowed impact: a publicly reachable fault in a production bridge path causing user fund loss without direct BTC/nBTC theft.

### Likelihood Explanation
`sign_btc_transaction` is called by every withdrawal and refund user who needs MPC signing. The NEAR chain signatures protocol charges a fee that can vary. Users who attach a round number or a conservative over-estimate (a common pattern when the exact fee is unknown) will silently lose the excess on every signing call. Because the bridge provides no view function for the required signing fee, over-payment is a realistic and recurring scenario.

### Recommendation
1. Add a `required_balance_for_sign` view function that queries or caches the chain signatures fee.
2. In `sign_promise` (or in `sign_btc_transaction_callback`), compute `excess = env::attached_deposit() - required_fee` and issue a `Promise::new(predecessor).transfer(excess)` refund when `excess > 0`, mirroring the pattern already used in `execute_refund` / `request_refund`.

### Proof of Concept
1. User initiates a withdrawal; bridge creates a `BTCPendingInfo` in `PendingSign` state.
2. User calls `sign_btc_transaction("pending_id", 0, 0)` attaching `2 NEAR` (a conservative over-estimate of the signing fee, which may be `0.2 NEAR`).
3. `sign_btc_transaction` → `internal_sign_btc_transaction` → `sign_promise` forwards the full `2 NEAR` to chain signatures via `.with_attached_deposit(env::attached_deposit())`.
4. Chain signatures consumes its required fee (`0.2 NEAR`) and either discards or refunds the remaining `1.8 NEAR` to the bridge contract.
5. `sign_btc_transaction_callback` executes with no refund logic; the `1.8 NEAR` excess is never returned to the user.
6. The user has permanently lost `1.8 NEAR` with no recourse.

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

**File:** contracts/satoshi-bridge/src/api/chain_signatures.rs (L19-26)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_btc_transaction(
        &mut self,
        btc_pending_sign_id: String,
        sign_index: usize,
        key_version: u32,
    ) -> PromiseOrValue<bool> {
```
