### Title
`chain_signatures_root_public_key` Cannot Be Updated Once Set, Permanently Locking Bridge Withdrawals on MPC Key Rotation - (File: `contracts/satoshi-bridge/src/api/management.rs`)

---

### Summary

The `sync_chain_signatures_root_public_key` function enforces a one-time-set guard that permanently prevents the DAO from updating the MPC root public key after it is first synced. Because `chain_signatures_root_public_key` is also absent from `ConfigUpdate`, there is no alternative update path. If the NEAR Chain Signatures MPC network rotates its root public key, the bridge is irrecoverably stuck: all withdrawal signing and UTXO address derivation will silently use the stale key, making every withdrawal fail and permanently locking all bridged BTC/ZEC.

---

### Finding Description

`sync_chain_signatures_root_public_key` in `contracts/satoshi-bridge/src/api/management.rs` contains the following guard:

```rust
pub fn sync_chain_signatures_root_public_key(&mut self) -> Promise {
    assert_one_yocto();
    require!(
        self.internal_config()
            .chain_signatures_root_public_key
            .is_none(),   // ← one-time-set guard
        "Already sync"
    );
    self.sync_chain_signatures_root_public_key_promise()
}
``` [1](#0-0) 

Once the callback `sync_root_public_key_callback` writes a `Some(root_public_key)` into `config.chain_signatures_root_public_key`, the guard fires on every subsequent call and the function reverts with `"Already sync"`. [2](#0-1) 

The `ConfigUpdate` struct — the only other mechanism for changing `Config` fields — does not include `chain_signatures_root_public_key` or `change_address`, so `update_config` cannot be used as a workaround. [3](#0-2) 

The frozen key is the sole input to all UTXO address derivation and BTC public-key generation:

```rust
pub fn generate_public_key(&self, path: &str) -> Vec<u8> {
    let mpc_pk = crypto_shared::near_public_key_to_affine_point(
        self.internal_config()
            .chain_signatures_root_public_key
            .clone()
            .expect("Missing chain_signatures_root_public_key"),
    );
    ...
}
``` [4](#0-3) 

`generate_btc_public_key` and `generate_utxo_chain_address` both call `generate_public_key`, so every withdrawal signing request and every deposit-address derivation depends on the frozen key. [5](#0-4) 

---

### Impact Explanation

If the NEAR Chain Signatures MPC network rotates its root public key (a normal operational event for MPC networks):

1. The bridge's stored `chain_signatures_root_public_key` becomes stale.
2. `generate_public_key` derives wrong child keys for every UTXO path.
3. All calls to `internal_sign_btc_transaction` produce signatures that do not match the actual on-chain UTXO scripts, causing every withdrawal to fail at broadcast or verification.
4. No withdrawal can ever succeed again without deploying a new contract, meaning all nBTC/nZEC holders are permanently unable to redeem their tokens for underlying BTC/ZEC.

This constitutes **permanent locking of user funds** — a Critical allowed impact — and at minimum a **stuck bridge state requiring operator intervention** — a Medium allowed impact.

---

### Likelihood Explanation

NEAR Chain Signatures is an active MPC network whose root public key can change due to resharing, validator-set rotation, or protocol upgrades. The bridge has no mechanism to adapt. The likelihood is **Medium**: the event is not adversarially triggered but is a foreseeable operational occurrence, and the consequence when it occurs is total withdrawal failure.

---

### Recommendation

Remove the `is_none()` guard from `sync_chain_signatures_root_public_key` so the DAO can re-sync the key at any time:

```rust
pub fn sync_chain_signatures_root_public_key(&mut self) -> Promise {
    assert_one_yocto();
    // Remove: require!(self.internal_config().chain_signatures_root_public_key.is_none(), "Already sync");
    self.sync_chain_signatures_root_public_key_promise()
}
```

Alternatively, add `chain_signatures_root_public_key: Option<PublicKey>` to `ConfigUpdate` so the DAO can set it directly, and emit an event on every update for auditability.

---

### Proof of Concept

1. Bridge is deployed and `sync_chain_signatures_root_public_key` is called once. `chain_signatures_root_public_key` is now `Some(old_key)`.
2. NEAR MPC network rotates its root public key to `new_key`.
3. DAO calls `sync_chain_signatures_root_public_key` again → **panics** with `"Already sync"`.
4. DAO calls `update_config` with any `ConfigUpdate` → `chain_signatures_root_public_key` is not a field; the key remains `old_key`.
5. A user calls `ft_transfer_call` to initiate a withdrawal. The bridge calls `generate_btc_public_key` using `old_key`, derives a wrong script, and requests an MPC signature over a payload that does not correspond to any real UTXO the bridge controls.
6. The signed transaction is invalid on Bitcoin; the withdrawal fails. Every subsequent withdrawal fails identically.
7. All nBTC/nZEC tokens are permanently unredeemable until a new contract is deployed and all state migrated.

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

**File:** contracts/satoshi-bridge/src/kdf.rs (L42-57)
```rust
    pub fn generate_btc_public_key(&self, path: &str) -> BtcPublicKey {
        let public_key_bytes = self.generate_public_key(path);
        let uncompressed_btc_public_key =
            BtcPublicKey::from_slice(&public_key_bytes).expect("Invalid public key bytes");
        uncompressed_btc_public_key
            .inner
            .to_string()
            .parse()
            .unwrap()
    }

    pub fn generate_utxo_chain_address(&self, path: &str) -> Address {
        let btc_public_key = self.generate_btc_public_key(path);
        Address::from_pubkey(self.internal_config().chain.clone(), btc_public_key)
            .expect("Invalid public key")
    }
```
