### Title
Missing Setter for `change_address` in Config Permanently Breaks Withdrawal Flow - (File: contracts/satoshi-bridge/src/config.rs)

### Summary

The `Config` struct contains a `change_address` field that is **required to be `None` at contract initialization**, yet the `ConfigUpdate` struct — the only mechanism for post-deployment config mutation — does not include a `change_address` field. There is no dedicated setter function anywhere in the management API. As a result, `change_address` is permanently `None` after deployment, and any withdrawal that requires a change output will panic with `"ERR_CONFIG: change_address not configured"`, permanently breaking the withdrawal path for all nBTC holders.

### Finding Description

The constructor enforces that `change_address` must be `None` at initialization: [1](#0-0) 

The `Config` struct declares `change_address` as `Option<String>`: [2](#0-1) 

The `get_change_script_pubkey()` method panics when `change_address` is `None`: [3](#0-2) 

The `ConfigUpdate` struct — applied by the DAO-only `update_config()` function — lists every updatable field, but **`change_address` is absent**: [4](#0-3) 

The `ConfigUpdate::apply()` method correspondingly has no `set_if_some!(change_address)` call: [5](#0-4) 

No other function in `management.rs`, `bridge.rs`, or any other production file provides a setter for `change_address`. The only view function for it is `get_change_address()`, which is read-only: [6](#0-5) 

### Impact Explanation

Every Bitcoin withdrawal transaction that produces change (i.e., where total UTXO input value exceeds withdrawal amount + fees — the overwhelming majority of real transactions) calls `get_change_script_pubkey()` during PSBT construction. This call panics unconditionally because `change_address` is always `None`. The panic propagates through `ft_on_transfer`, causing the NEP-141 `ft_transfer_call` to fail and refund the user's nBTC. Users cannot exit the bridge to native BTC. The bridge is in a permanently stuck withdrawal state that cannot be resolved without a contract upgrade, since the DAO has no setter to provide.

**Impact: Low** — Publicly reachable panic-driven fault in the production withdrawal path. No direct fund theft (nBTC is returned on panic), but the withdrawal bridge path is permanently broken for all users.

### Likelihood Explanation

This is triggered by any nBTC holder attempting a standard withdrawal via `ft_transfer_call`. It requires no special privileges, no attacker coordination, and no external conditions — it fires on the very first withdrawal attempt after deployment. Likelihood is **certain** once the bridge is live and a user tries to withdraw.

### Recommendation

Add `change_address: Option<String>` to `ConfigUpdate` and a corresponding `set_if_some!(change_address)` call in `ConfigUpdate::apply()`. Additionally, remove or relax the constructor's `require!(config.change_address.is_none(), ...)` guard, or provide a dedicated `set_change_address` management function gated to `Role::DAO`, so the operator can configure the change address before the bridge accepts withdrawals.

### Proof of Concept

1. Deploy the contract with any valid `Config` where `change_address: None` (the constructor enforces this).
2. Attempt to call `update_config` with any `ConfigUpdate` — `change_address` is not a field, so it cannot be set.
3. Any nBTC holder calls `ft_transfer_call` on the nBTC contract to initiate a withdrawal.
4. The bridge's `ft_on_transfer` → PSBT construction → `config.get_change_script_pubkey()` panics: `"ERR_CONFIG: change_address not configured"`.
5. The `ft_transfer_call` resolves the failure and returns nBTC to the user; the withdrawal never executes.
6. This repeats for every withdrawal attempt by every user, permanently.

### Citations

**File:** contracts/satoshi-bridge/src/lib.rs (L189-192)
```rust
        require!(
            config.change_address.is_none(),
            "Init change_address must be None"
        );
```

**File:** contracts/satoshi-bridge/src/config.rs (L58-59)
```rust
    // The change address of BTC transaction
    pub change_address: Option<String>,
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L474-478)
```rust
    pub fn get_change_address(&self) -> Option<String> {
        let config = self.internal_config();
        config.change_address.clone()
    }
}
```
