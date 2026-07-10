### Title
`sync_chain_signatures_root_public_key` Is a One-Shot Write With No Update Path — MPC Root Key Rotation Permanently Breaks All Withdrawals - (File: `contracts/satoshi-bridge/src/api/management.rs`)

---

### Summary

`sync_chain_signatures_root_public_key` enforces a one-time-only write guard (`is_none()` check). Once the MPC root public key is stored, it can never be refreshed. `ConfigUpdate` also omits `chain_signatures_root_public_key` entirely. If the NEAR Chain Signatures MPC network rotates its root public key — a supported and anticipated operation evidenced by the `key_version` parameter in every signing request — the bridge's KDF will permanently derive wrong addresses and produce invalid signatures, with no on-chain recovery path.

---

### Finding Description

`sync_chain_signatures_root_public_key` in `management.rs` enforces a hard one-time guard:

```rust
require!(
    self.internal_config()
        .chain_signatures_root_public_key
        .is_none(),
    "Already sync"
);
``` [1](#0-0) 

Once the callback `sync_root_public_key_callback` writes the key, the field is `Some(...)` forever:

```rust
self.internal_mut_config().chain_signatures_root_public_key = Some(root_public_key);
``` [2](#0-1) 

`ConfigUpdate` — the only other write path — does not include `chain_signatures_root_public_key` or `chain_signatures_account_id` as updatable fields: [3](#0-2) 

Every withdrawal signing call derives BTC public keys and the hash-to-sign from this frozen root key:

```rust
let mpc_pk = crypto_shared::near_public_key_to_affine_point(
    self.internal_config()
        .chain_signatures_root_public_key
        .clone()
        .expect("Missing chain_signatures_root_public_key"),
);
``` [4](#0-3) 

The `sign_btc_transaction` public entry point passes a caller-supplied `key_version` to the MPC, signalling that the protocol explicitly anticipates multiple key versions: [5](#0-4) 

When the MPC rotates to a new key version, it signs with a new root key. The bridge, however, still computes the hash-to-sign using the old derived public key. The resulting signature is invalid for the old address, so `sign_btc_transaction_callback` stores a bad signature, and the assembled transaction is unspendable on Bitcoin. [6](#0-5) 

Additionally, `sync_root_public_key_callback` also derives and stores the bridge's change address from the root key:

```rust
let change_address = self
    .generate_utxo_chain_address(env::current_account_id().as_str())
    .to_string();
self.internal_mut_config().change_address = Some(change_address);
``` [7](#0-6) 

After a key rotation, the change address is also stale — change outputs in every new transaction go to an address the MPC can no longer sign for, permanently locking those satoshis.

---

### Impact Explanation

After an MPC root key rotation:

1. Every call to `sign_btc_transaction` produces a signature that is cryptographically invalid for the UTXO being spent. The assembled Bitcoin transaction cannot be broadcast successfully.
2. The bridge's change address becomes an address for which the MPC holds no signing key. Any change output is permanently unspendable.
3. `sync_chain_signatures_root_public_key` always reverts with `"Already sync"`, and `update_config` has no field for this value, so there is no on-chain recovery path.
4. All user funds locked in pending withdrawals, and all bridge-held UTXOs that would receive change, are permanently frozen.

This matches: **Medium — stuck bridge state requiring operator intervention** (with no operator path to resolve it), and potentially **Critical — permanent locking of user or protocol funds** for UTXOs whose change address is now uncontrolled.

---

### Likelihood Explanation

NEAR Chain Signatures is a live MPC network that explicitly supports key versioning (`key_version` in `SignRequest`). Key rotation is a standard operational procedure for MPC networks during upgrades, resharing, or security incidents. The `key_version` parameter being present in the bridge's own signing API confirms the protocol designers anticipated this. The trigger is an external network event, but the root cause — the absence of any update path — is entirely within the bridge contract.

---

### Recommendation

1. Remove the `is_none()` guard from `sync_chain_signatures_root_public_key` so DAO can re-sync the root public key at any time (or add a separate `force_sync_chain_signatures_root_public_key` that skips the guard).
2. Add `chain_signatures_root_public_key: Option<PublicKey>` and `chain_signatures_account_id: Option<AccountId>` to `ConfigUpdate` so governance can update them via `update_config`.
3. When the root public key is updated, re-derive and update `change_address` atomically in the same transaction.

---

### Proof of Concept

1. Bridge is deployed; DAO calls `sync_chain_signatures_root_public_key`. Callback stores `root_pk_v0` and derives `change_address_v0`.
2. NEAR Chain Signatures MPC performs a key rotation; the network now uses `root_pk_v1`.
3. DAO attempts to call `sync_chain_signatures_root_public_key` again → **panics: "Already sync"**.
4. DAO attempts `update_config` with a new root key → **no such field in `ConfigUpdate`**, call is a no-op for this value.
5. Any user calls `sign_btc_transaction(pending_id, 0, key_version=1)`. The bridge computes `hash_to_sign` using `root_pk_v0`-derived public key. MPC signs with `root_pk_v1`. The stored signature is invalid for the UTXO's locking script.
6. The signed transaction is broadcast and rejected by the Bitcoin network. The UTXO remains unspent and locked in the bridge forever.
7. All future withdrawals and change outputs are similarly broken. No on-chain function can update the root key.

### Citations

**File:** contracts/satoshi-bridge/src/api/management.rs (L270-274)
```rust
        require!(
            self.internal_config()
                .chain_signatures_root_public_key
                .is_none(),
            "Already sync"
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L123-123)
```rust
            self.internal_mut_config().chain_signatures_root_public_key = Some(root_public_key);
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L124-127)
```rust
            let change_address = self
                .generate_utxo_chain_address(env::current_account_id().as_str())
                .to_string();
            self.internal_mut_config().change_address = Some(change_address);
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L141-170)
```rust
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
```

**File:** contracts/satoshi-bridge/src/config.rs (L223-263)
```rust
#[near(serializers = [json])]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug))]
pub struct ConfigUpdate {
    pub btc_light_client_account_id: Option<AccountId>,
    pub nbtc_account_id: Option<AccountId>,
    pub confirmations_delta: Option<u8>,
    pub extra_msg_confirmations_delta: Option<u8>,
    pub deposit_bridge_fee: Option<BridgeFee>,
    pub withdraw_bridge_fee: Option<BridgeFee>,
    #[serde(with = "u128_dec_format_option")]
    #[serde(default)]
    pub min_deposit_amount: Option<u128>,
    #[serde(with = "u128_dec_format_option")]
    #[serde(default)]
    pub min_withdraw_amount: Option<u128>,
    #[serde(with = "u128_dec_format_option")]
    #[serde(default)]
    pub min_change_amount: Option<u128>,
    #[serde(with = "u128_dec_format_option")]
    #[serde(default)]
    pub max_change_amount: Option<u128>,
    #[serde(with = "u128_dec_format_option")]
    #[serde(default)]
    pub min_btc_gas_fee: Option<u128>,
    #[serde(with = "u128_dec_format_option")]
    #[serde(default)]
    pub max_btc_gas_fee: Option<u128>,
    pub max_withdrawal_input_number: Option<u8>,
    pub max_change_number: Option<u8>,
    pub max_active_utxo_management_input_number: Option<u8>,
    pub max_active_utxo_management_output_number: Option<u8>,
    pub active_management_lower_limit: Option<u32>,
    pub active_management_upper_limit: Option<u32>,
    pub passive_management_lower_limit: Option<u32>,
    pub passive_management_upper_limit: Option<u32>,
    pub rbf_num_limit: Option<u8>,
    pub max_btc_tx_pending_sec: Option<u32>,
    pub unhealthy_utxo_amount: Option<u64>,
    pub refund_timelock_sec: Option<u64>,
    pub unsafe_refund_timelock_sec: Option<u64>,
}
```

**File:** contracts/satoshi-bridge/src/kdf.rs (L29-35)
```rust
    pub fn generate_public_key(&self, path: &str) -> Vec<u8> {
        let mpc_pk = crypto_shared::near_public_key_to_affine_point(
            self.internal_config()
                .chain_signatures_root_public_key
                .clone()
                .expect("Missing chain_signatures_root_public_key"),
        );
```

**File:** contracts/satoshi-bridge/src/api/chain_signatures.rs (L21-43)
```rust
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
