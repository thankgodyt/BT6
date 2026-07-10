### Title
`chain_signatures_root_public_key` Can Only Be Synced Once — No Re-Sync Mechanism After MPC Key Rotation - (File: `contracts/satoshi-bridge/src/api/management.rs`)

### Summary
The `satoshi-bridge` contract caches the MPC root public key in `Config.chain_signatures_root_public_key` via `sync_chain_signatures_root_public_key`, but a hard `require!(is_none(), "Already sync")` guard makes this a one-time-only operation. Additionally, `chain_signatures_account_id` is absent from `ConfigUpdate`, so it too can never be changed after initialization. If the NEAR Chain Signatures MPC network rotates its root public key or migrates to a new contract account, the bridge has no path — even for the DAO — to update these values, leaving the bridge in a permanently broken state.

### Finding Description

`Config` stores two critical MPC-related fields:

```rust
// contracts/satoshi-bridge/src/config.rs lines 54-57
pub chain_signatures_account_id: AccountId,
pub chain_signatures_root_public_key: Option<PublicKey>,
```

The only update path for the root public key is `sync_chain_signatures_root_public_key` in `management.rs`:

```rust
// contracts/satoshi-bridge/src/api/management.rs lines 268-277
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

Once `chain_signatures_root_public_key` is `Some(...)`, this function permanently panics with `"Already sync"`. There is no alternative setter.

The `ConfigUpdate` struct, which backs the `update_config` DAO function, lists every updatable field — but `chain_signatures_account_id` is not among them:

```rust
// contracts/satoshi-bridge/src/config.rs lines 225-263
pub struct ConfigUpdate {
    pub btc_light_client_account_id: Option<AccountId>,
    pub nbtc_account_id: Option<AccountId>,
    // ... many other fields ...
    // chain_signatures_account_id is ABSENT
}
```

The `ConfigUpdate::apply` macro loop confirms only `btc_light_client_account_id` and `nbtc_account_id` are applied; `chain_signatures_account_id` is never touched.

When `sync_root_public_key_callback` runs, it also derives and permanently stores the bridge's BTC `change_address` from the root public key:

```rust
// contracts/satoshi-bridge/src/chain_signature.rs lines 124-127
let change_address = self
    .generate_utxo_chain_address(env::current_account_id().as_str())
    .to_string();
self.internal_mut_config().change_address = Some(change_address);
```

`change_address` is also absent from `ConfigUpdate`, so it cannot be independently corrected either.

### Impact Explanation

If the NEAR Chain Signatures MPC network rotates its root public key (a normal operational event in threshold-signature systems) or migrates to a new contract account:

1. **`chain_signatures_account_id` cannot be updated** — all calls to `sign_promise` and `sync_chain_signatures_root_public_key_promise` will target the old/defunct contract, causing every withdrawal signing attempt to fail permanently.
2. **`chain_signatures_root_public_key` cannot be re-synced** — the KDF used to derive per-user deposit addresses and the bridge's own `change_address` will continue using the stale key. BTC change outputs during withdrawals will be sent to an address the MPC can no longer sign for, permanently locking those funds in the bridge's UTXO pool.
3. **No DAO escape hatch exists** — even a fully cooperative DAO cannot fix either field without a contract upgrade, which itself requires a time-locked staging process.

This matches the Medium impact class: stuck bridge state requiring operator intervention, with potential for permanent locking of bridge-controlled UTXO funds.

### Likelihood Explanation

NEAR Chain Signatures is an active MPC protocol under development. Key rotation and contract migration are standard operational events for MPC networks. The NEAR ecosystem has already undergone multiple contract migrations. The bridge's inability to respond to any such event is a structural gap, not a theoretical edge case.

### Recommendation

1. Remove the `require!(is_none(), "Already sync")` guard from `sync_chain_signatures_root_public_key` and replace it with a DAO-gated re-sync that also recomputes and updates `change_address`.
2. Add `chain_signatures_account_id: Option<AccountId>` to `ConfigUpdate` and handle it in `ConfigUpdate::apply`, mirroring the existing pattern for `btc_light_client_account_id`.
3. Add `change_address: Option<String>` to `ConfigUpdate` so the DAO can manually correct the change address if needed independently of a full re-sync.

### Proof of Concept

**State after initial sync:**
- `config.chain_signatures_root_public_key = Some(old_key)`
- `config.change_address = Some(address_derived_from_old_key)`
- `config.chain_signatures_account_id = "v1.chain-signatures.near"`

**MPC rotates key / migrates contract to `"v2.chain-signatures.near"`.**

**DAO attempts to fix:**
```
call update_config({ "chain_signatures_account_id": "v2.chain-signatures.near" })
→ field is absent from ConfigUpdate; silently ignored; no update occurs
```
```
call sync_chain_signatures_root_public_key()
→ panics: "Already sync"
```

**Result:** Every subsequent `sign_btc_transaction` call targets `"v1.chain-signatures.near"` (defunct). All withdrawal signing fails. BTC change outputs continue flowing to `address_derived_from_old_key`, which the new MPC key cannot sign for. Bridge is permanently stuck; protocol-controlled UTXOs are locked with no recovery path short of a contract upgrade. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** contracts/satoshi-bridge/src/config.rs (L51-57)
```rust
    pub btc_light_client_account_id: AccountId,
    // The account id of nbtc contract
    pub nbtc_account_id: AccountId,
    // The account id of chain signatures contract
    pub chain_signatures_account_id: AccountId,
    // The root public key of chain signatures contract
    pub chain_signatures_root_public_key: Option<PublicKey>,
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

**File:** contracts/satoshi-bridge/src/config.rs (L265-301)
```rust
impl ConfigUpdate {
    pub fn apply(self, config: &mut Config) {
        macro_rules! set_if_some {
            ($field:ident) => {
                if let Some(v) = self.$field {
                    config.$field = v;
                }
            };
        }
        set_if_some!(btc_light_client_account_id);
        set_if_some!(nbtc_account_id);
        set_if_some!(confirmations_delta);
        set_if_some!(extra_msg_confirmations_delta);
        set_if_some!(deposit_bridge_fee);
        set_if_some!(withdraw_bridge_fee);
        set_if_some!(min_deposit_amount);
        set_if_some!(min_withdraw_amount);
        set_if_some!(min_change_amount);
        set_if_some!(max_change_amount);
        set_if_some!(min_btc_gas_fee);
        set_if_some!(max_btc_gas_fee);
        set_if_some!(max_withdrawal_input_number);
        set_if_some!(max_change_number);
        set_if_some!(max_active_utxo_management_input_number);
        set_if_some!(max_active_utxo_management_output_number);
        set_if_some!(active_management_lower_limit);
        set_if_some!(active_management_upper_limit);
        set_if_some!(passive_management_lower_limit);
        set_if_some!(passive_management_upper_limit);
        set_if_some!(rbf_num_limit);
        set_if_some!(max_btc_tx_pending_sec);
        set_if_some!(unhealthy_utxo_amount);
        set_if_some!(refund_timelock_sec);
        set_if_some!(unsafe_refund_timelock_sec);

        config.assert_valid();
    }
```

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
