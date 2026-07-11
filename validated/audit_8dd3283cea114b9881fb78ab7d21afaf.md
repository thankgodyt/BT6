### Title
Missing Setter for `change_address` Permanently Blocks All Withdrawals - (File: contracts/satoshi-bridge/src/config.rs, contracts/satoshi-bridge/src/api/management.rs)

### Summary
The `Config.change_address` field is required to be `None` at contract initialization, but no public function exists to set it afterward. The `ConfigUpdate` struct used by `update_config` omits `change_address`, and no dedicated setter is provided. Because `get_change_script_pubkey()` panics when `change_address` is `None`, every withdrawal attempt permanently fails, leaving the bridge in a stuck state that requires a contract upgrade to resolve.

### Finding Description
The `Contract::new()` initializer enforces that `change_address` must be `None`:

```rust
require!(
    config.change_address.is_none(),
    "Init change_address must be None"
);
``` [1](#0-0) 

After initialization, the only mechanism to update configuration is `update_config`, which applies a `ConfigUpdate` struct. Comparing `Config` to `ConfigUpdate`, the `change_address` field is entirely absent from `ConfigUpdate`: [2](#0-1) 

The `ConfigUpdate::apply` macro only sets fields present in the struct, so `change_address` can never be written: [3](#0-2) 

No other management function in `management.rs` sets `change_address`: [4](#0-3) 

When any withdrawal is initiated, `create_btc_pending_info` calls `check_withdraw_psbt_valid`, which calls `get_change_script_pubkey()`: [5](#0-4) 

This panics unconditionally when `change_address` is `None`:

```rust
self.change_address
    .as_ref()
    .expect("ERR_CONFIG: change_address not configured")
``` [5](#0-4) 

By contrast, `chain_signatures_root_public_key` — another field that must be `None` at init — has a dedicated post-init setter (`sync_chain_signatures_root_public_key`). No equivalent exists for `change_address`. [6](#0-5) 

### Impact Explanation
Every nBTC → BTC withdrawal triggers `get_change_script_pubkey()`, which panics when `change_address` is `None`. Because the bridge is forced to initialize with `change_address = None` and has no setter, the withdrawal path is permanently broken from genesis. Active UTXO management (`active_utxo_management`) also calls this path and is equally broken. The bridge is stuck in a state where no withdrawal can ever succeed, requiring a contract upgrade to recover. This matches the allowed impact: **stuck bridge state requiring operator intervention**.

### Likelihood Explanation
The failure is triggered by the very first withdrawal attempt by any ordinary nBTC holder calling `ft_transfer_call` with a `Withdraw` message. No special privileges or knowledge are required. The panic occurs deterministically on every withdrawal call as long as `change_address` remains `None`, which it always will be given the missing setter.

### Recommendation
Add a dedicated DAO-gated setter for `change_address` in `management.rs`, mirroring the pattern used for `sync_chain_signatures_root_public_key`:

```rust
#[payable]
#[access_control_any(roles(Role::DAO))]
pub fn set_change_address(&mut self, change_address: Option<String>) {
    assert_one_yocto();
    self.internal_mut_config().change_address = change_address;
}
```

Alternatively, add `change_address: Option<String>` to `ConfigUpdate` and handle it in `ConfigUpdate::apply`.

### Proof of Concept
1. Deploy the bridge contract. `new()` enforces `config.change_address.is_none()`.
2. Call `get_config()` — observe `change_address: null`.
3. Call `update_config({})` with any valid `ConfigUpdate` — `change_address` remains `null` because the field is absent from `ConfigUpdate`.
4. As any nBTC holder, call `ft_transfer_call` on the nBTC contract with `msg = {"Withdraw": {...}}`.
5. The bridge's `ft_on_transfer` → `create_btc_pending_info` → `check_withdraw_psbt_valid` → `get_change_script_pubkey()` panics with `"ERR_CONFIG: change_address not configured"`.
6. The withdrawal reverts; the bridge can never process any withdrawal without a contract upgrade.

### Citations

**File:** contracts/satoshi-bridge/src/lib.rs (L188-191)
```rust
        );
        require!(
            config.change_address.is_none(),
            "Init change_address must be None"
```

**File:** contracts/satoshi-bridge/src/config.rs (L160-166)
```rust
    pub fn get_change_script_pubkey(&self) -> ScriptBuf {
        self.string_to_script_pubkey(
            self.change_address
                .as_ref()
                .expect("ERR_CONFIG: change_address not configured"),
        )
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

**File:** contracts/satoshi-bridge/src/config.rs (L266-301)
```rust
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

**File:** contracts/satoshi-bridge/src/api/management.rs (L264-277)
```rust
#[near]
impl Contract {
    #[payable]
    #[access_control_any(roles(Role::DAO))]
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

**File:** contracts/satoshi-bridge/src/api/management.rs (L279-314)
```rust
    #[payable]
    #[access_control_any(roles(Role::DAO))]
    pub fn update_config(&mut self, update: ConfigUpdate) {
        assert_one_yocto();
        update.apply(self.internal_mut_config());
    }

    #[payable]
    #[access_control_any(roles(Role::DAO))]
    pub fn set_confirmations_strategy(&mut self, range_upper_bound: U128, confirmations: u8) {
        assert_one_yocto();

        let config = self.internal_mut_config();
        config
            .confirmations_strategy
            .insert(range_upper_bound.0.to_string(), confirmations);

        config.assert_valid()
    }

    #[payable]
    #[access_control_any(roles(Role::DAO))]
    pub fn remove_confirmations_strategy(&mut self, range_upper_bound: U128) {
        assert_one_yocto();
        let is_success = self
            .internal_mut_config()
            .confirmations_strategy
            .remove(&range_upper_bound.0.to_string())
            .is_some();
        require!(is_success, "Invalid range_upper_bound");
        require!(
            !self.internal_config().confirmations_strategy.is_empty(),
            "confirmations_strategy must not be empty"
        );
    }
}
```
