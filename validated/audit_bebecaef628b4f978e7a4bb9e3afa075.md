### Title
`sync_chain_signatures_root_public_key` Can Only Be Called Once — MPC Root Key Rotation Permanently Locks All Bridge-Controlled Funds - (File: contracts/satoshi-bridge/src/api/management.rs)

### Summary

`sync_chain_signatures_root_public_key` enforces a one-time-only guard (`"Already sync"`) that permanently prevents the bridge from updating its stored MPC root public key. Because every BTC/ZEC deposit address and every withdrawal signing operation is derived from this key, a NEAR Chain Signatures (MPC) root key rotation would make all bridge-controlled UTXOs permanently inaccessible with no on-chain recovery path.

### Finding Description

`sync_chain_signatures_root_public_key` is the sole mechanism for setting `Config::chain_signatures_root_public_key`:

```rust
// contracts/satoshi-bridge/src/api/management.rs
pub fn sync_chain_signatures_root_public_key(&mut self) -> Promise {
    assert_one_yocto();
    require!(
        self.internal_config()
            .chain_signatures_root_public_key
            .is_none(),
        "Already sync"   // ← hard block after first call
    );
    self.sync_chain_signatures_root_public_key_promise()
}
```

Once the callback `sync_root_public_key_callback` writes the key into config, the guard fires on every subsequent call and the function becomes permanently inoperable. [1](#0-0) 

The `update_config` function accepts a `ConfigUpdate` struct, but that struct deliberately omits both `chain_signatures_root_public_key` and `change_address`:

```rust
// contracts/satoshi-bridge/src/config.rs  lines 225-263
pub struct ConfigUpdate {
    pub btc_light_client_account_id: Option<AccountId>,
    pub nbtc_account_id: Option<AccountId>,
    // ... many fields ...
    // chain_signatures_root_public_key: ABSENT
    // change_address: ABSENT
}
``` [2](#0-1) 

There is therefore **no on-chain path** to update the stored root public key after initial deployment.

The root public key is the foundation of all key derivation in `kdf.rs`:

```rust
pub fn generate_public_key(&self, path: &str) -> Vec<u8> {
    let mpc_pk = crypto_shared::near_public_key_to_affine_point(
        self.internal_config()
            .chain_signatures_root_public_key
            .clone()
            .expect("Missing chain_signatures_root_public_key"),
    );
    // ... derive per-UTXO key from mpc_pk ...
}
``` [3](#0-2) 

Every deposit address (`generate_utxo_chain_address`), every withdrawal signing payload (`internal_sign_btc_transaction`), and every refund signing operation derives its public key from this single frozen value. [4](#0-3) [5](#0-4) 

The `change_address` is also permanently frozen at the same time — it is computed once inside `sync_root_public_key_callback` and is equally absent from `ConfigUpdate`:

```rust
// chain_signature.rs
self.internal_mut_config().chain_signatures_root_public_key = Some(root_public_key);
let change_address = self
    .generate_utxo_chain_address(env::current_account_id().as_str())
    .to_string();
self.internal_mut_config().change_address = Some(change_address);
``` [6](#0-5) 

### Impact Explanation

If the NEAR Chain Signatures MPC network rotates its root public key (a normal operational security event):

1. The bridge's stored `chain_signatures_root_public_key` becomes stale.
2. `generate_btc_public_key` derives the wrong public keys for all UTXOs.
3. Every call to `sign_btc_transaction` produces a signature that does not match the UTXO's locking script — all withdrawals fail permanently.
4. All refund signing fails for the same reason.
5. All BTC/ZEC held in bridge-controlled UTXOs (derived from the old key) become permanently inaccessible on-chain.
6. There is no on-chain recovery path; a contract upgrade is the only escape, and even then the old UTXOs remain unspendable because the MPC no longer holds the old key.

This matches the allowed impact: **Medium — stuck bridge state requiring operator intervention**, with the realistic worst-case of **Critical — permanent locking of all bridge-controlled user funds**.

### Likelihood Explanation

NEAR Chain Signatures is an actively evolving MPC network. Key rotation is a standard operational practice for threshold signature schemes and is explicitly supported by the MPC protocol (`key_version` field in `SignRequest`). The bridge already passes `key_version` as a parameter to `sign`, acknowledging that multiple key versions exist. The probability of a root key rotation over the bridge's operational lifetime is non-trivial. [7](#0-6) 

### Recommendation

Remove the `is_none()` guard from `sync_chain_signatures_root_public_key` so that DAO can re-sync the key at any time. Alternatively, add a separate DAO-gated `force_sync_chain_signatures_root_public_key` that skips the guard, or include `chain_signatures_root_public_key` as an updatable field in `ConfigUpdate`. When the root key changes, `change_address` must also be recomputed (as it already is inside `sync_root_public_key_callback`), so the existing callback logic is correct — only the one-time guard needs to be removed.

### Proof of Concept

1. Bridge is deployed and `sync_chain_signatures_root_public_key` is called once. `chain_signatures_root_public_key = Some(K_old)` and `change_address = addr(K_old)`.
2. NEAR MPC rotates its root key to `K_new`.
3. DAO calls `sync_chain_signatures_root_public_key` again → **panics with "Already sync"**.
4. DAO calls `update_config({...})` → `chain_signatures_root_public_key` is not a field in `ConfigUpdate`, so it cannot be updated this way either.
5. A user initiates a withdrawal. `internal_sign_btc_transaction` calls `generate_btc_public_key(path)` which derives a key from `K_old`. The MPC signs with `K_new`. The resulting signature does not satisfy the UTXO's P2WPKH/P2PKH locking script. The withdrawal transaction is invalid and will never confirm on-chain.
6. All bridge UTXOs are permanently locked. No further withdrawals or refunds are possible without a contract upgrade — and even after an upgrade, the UTXOs locked to `K_old`-derived addresses remain unspendable because the MPC no longer controls `K_old`.

### Citations

**File:** contracts/satoshi-bridge/src/api/management.rs (L268-277)
```rust
    pub fn sync_chain_signatures_root_public_key(&mut self) -> Promise {
        assert_one_yocto();
        require!(
            self.internal_config()
                .chain_signatures_root_public_key
                .is_none(),
            "Already sync"
        );
        self.sync_chain_signatures_root_public_key_promise()
    }
```

**File:** contracts/satoshi-bridge/src/config.rs (L225-263)
```rust
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

**File:** contracts/satoshi-bridge/src/kdf.rs (L29-40)
```rust
    pub fn generate_public_key(&self, path: &str) -> Vec<u8> {
        let mpc_pk = crypto_shared::near_public_key_to_affine_point(
            self.internal_config()
                .chain_signatures_root_public_key
                .clone()
                .expect("Missing chain_signatures_root_public_key"),
        );
        let epsilon = derive_epsilon(env::current_account_id().as_ref(), path);
        let user_pk = crypto_shared::derive_key(mpc_pk, epsilon);
        let user_pk_encoded_point = user_pk.to_encoded_point(false);
        user_pk_encoded_point.as_bytes().to_vec()
    }
```

**File:** contracts/satoshi-bridge/src/kdf.rs (L53-57)
```rust
    pub fn generate_utxo_chain_address(&self, path: &str) -> Address {
        let btc_public_key = self.generate_btc_public_key(path);
        Address::from_pubkey(self.internal_config().chain.clone(), btc_public_key)
            .expect("Invalid public key")
    }
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L10-15)
```rust
#[near(serializers = [borsh, json])]
pub struct SignRequest {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L76-113)
```rust
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

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L119-132)
```rust
    pub fn sync_root_public_key_callback(&mut self) -> bool {
        if let Ok(result_bytes) = env::promise_result_checked(0, MAX_PUBLIC_KEY_RESULT) {
            let root_public_key =
                serde_json::from_slice::<PublicKey>(&result_bytes).expect("Invalid PublicKey");
            self.internal_mut_config().chain_signatures_root_public_key = Some(root_public_key);
            let change_address = self
                .generate_utxo_chain_address(env::current_account_id().as_str())
                .to_string();
            self.internal_mut_config().change_address = Some(change_address);
            true
        } else {
            false
        }
    }
```
