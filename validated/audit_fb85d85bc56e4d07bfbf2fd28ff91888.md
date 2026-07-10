### Title
`chain_signatures_root_public_key` is permanently locked after first sync with no re-sync path — (File: `contracts/satoshi-bridge/src/api/management.rs`)

---

### Summary

The `sync_chain_signatures_root_public_key` function contains a one-time-only guard that permanently prevents re-syncing the MPC root public key. Simultaneously, `chain_signatures_account_id` is absent from `ConfigUpdate`, making it impossible to update via `update_config`. If the NEAR Chain Signatures MPC network rotates its root public key or migrates to a new contract account, the bridge has no recovery path: deposit address derivation and all withdrawal signing become permanently broken.

---

### Finding Description

**Root cause 1 — one-time-only sync guard:**

`sync_chain_signatures_root_public_key` in `management.rs` (lines 268–277) enforces:

```rust
require!(
    self.internal_config().chain_signatures_root_public_key.is_none(),
    "Already sync"
);
``` [1](#0-0) 

Once the callback `sync_root_public_key_callback` writes the key into `chain_signatures_root_public_key` (and simultaneously derives and stores `change_address`), the guard fires on every subsequent call, making the stored root public key immutable for the lifetime of the contract. [2](#0-1) 

**Root cause 2 — `chain_signatures_account_id` absent from `ConfigUpdate`:**

`ConfigUpdate` (config.rs lines 225–263) lists every field that `update_config` can patch. `chain_signatures_account_id` is not among them. [3](#0-2) 

No other management function updates this field. The only place it is written is inside `Config` at initialization time. [4](#0-3) 

**How the locked values are used:**

`chain_signatures_account_id` is the cross-contract call target for every MPC signing request and for the root-public-key fetch itself. [5](#0-4) 

`chain_signatures_root_public_key` is consumed by `generate_btc_public_key` (via `kdf.rs`) to derive the secp256k1 public key for every UTXO path, which in turn determines every deposit address and every signing payload. [6](#0-5) 

---

### Impact Explanation

If the NEAR Chain Signatures MPC network rotates its root public key or the MPC contract is redeployed under a new account ID (both realistic operational events for an actively developed protocol):

1. **Deposit addresses become wrong.** All new deposit addresses are derived from the stale root key; funds sent to them cannot be claimed by the bridge.
2. **All withdrawals fail.** `sign_promise` targets the stale `chain_signatures_account_id`; every MPC signing call either reaches the wrong contract or produces signatures over keys the new MPC network does not recognize.
3. **`change_address` is also stale.** It is derived once inside `sync_root_public_key_callback` and stored permanently; it cannot be refreshed without re-syncing the root key, which is blocked.

The bridge enters a permanently stuck state. No user-facing recovery path exists short of a full contract upgrade and migration. This matches the **Medium** allowed impact: *stuck bridge state requiring operator intervention*.

---

### Likelihood Explanation

NEAR Chain Signatures is an actively developed MPC protocol. Key-version upgrades (`key_version` field in `SignRequest` already anticipates versioning) and contract migrations are foreseeable operational events. The guard `"Already sync"` was presumably added to prevent accidental double-initialization, but it inadvertently makes the root key immutable. Likelihood is low-to-medium given the protocol's maturity stage.

---

### Recommendation

1. **Remove the one-time guard** from `sync_chain_signatures_root_public_key` so the DAO can re-sync the root public key (and consequently refresh `change_address`) whenever the MPC network is upgraded.
2. **Add `chain_signatures_account_id`** as an optional field in `ConfigUpdate` so the DAO can redirect the bridge to a migrated MPC contract without a full redeployment.
3. Consider emitting an event when either value is updated to maintain auditability.

---

### Proof of Concept

1. DAO deploys bridge, calls `sync_chain_signatures_root_public_key` → `chain_signatures_root_public_key` is set to `pk_v1`, `change_address` is derived from `pk_v1`.
2. NEAR Chain Signatures rotates its root key to `pk_v2` (or migrates to `chain-sigs-v2.near`).
3. DAO calls `sync_chain_signatures_root_public_key` again → **panics: "Already sync"**.
4. All subsequent `sign_btc_transaction` calls derive signing payloads using `pk_v1`; the MPC network signs with `pk_v2` keys → signatures are invalid or the cross-contract call targets the wrong account.
5. All withdrawals revert; all new deposit addresses are unreachable. Bridge is permanently stuck with no on-chain recovery path.

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

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L62-74)
```rust
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

**File:** contracts/satoshi-bridge/src/config.rs (L54-57)
```rust
    // The account id of chain signatures contract
    pub chain_signatures_account_id: AccountId,
    // The root public key of chain signatures contract
    pub chain_signatures_root_public_key: Option<PublicKey>,
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

**File:** contracts/satoshi-bridge/src/lib.rs (L182-195)
```rust
    #[init]
    pub fn new(config: Config) -> Self {
        config.assert_valid();
        require!(
            config.chain_signatures_root_public_key.is_none(),
            "Init chain_signatures_root_public_key must be None"
        );
        require!(
            config.change_address.is_none(),
            "Init change_address must be None"
        );
        let mut contract = Self {
            data: VersionedContractData::Current(ContractData {
                config: LazyOption::new(StorageKey::Config, Some(config)),
```
