### Title
One-Time-Only `chain_signatures_root_public_key` Sync Permanently Breaks All Withdrawals on MPC Key Rotation — (`contracts/satoshi-bridge/src/api/management.rs`)

---

### Summary

The bridge stores the NEAR MPC network's root public key once via `sync_chain_signatures_root_public_key` and enforces a hard guard that prevents it from ever being updated again. If the NEAR chain-signatures service rotates its root public key — a normal operational event — every subsequent MPC signature verification for withdrawals will fail, permanently blocking all user withdrawals and locking all bridge-held BTC/ZEC.

---

### Finding Description

`sync_chain_signatures_root_public_key` in `management.rs` contains an explicit one-time-only guard:

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
``` [1](#0-0) 

Once the key is stored, the `require!` panics on every subsequent call. There is no `update_chain_signatures_root_public_key` or equivalent path. The `ConfigUpdate` struct, which covers all other updatable parameters, does not include `chain_signatures_root_public_key`: [2](#0-1) 

The key is stored in `Config` as `Option<PublicKey>`: [3](#0-2) 

and is used to verify every MPC signature produced by the chain-signatures service during the withdrawal pipeline. The withdrawal flow (`ft_transfer_call` → `sign_btc_transaction` → `verify_withdraw_burn_callback`) depends entirely on this key being current and valid. [4](#0-3) 

---

### Impact Explanation

If the NEAR MPC / chain-signatures service rotates its root public key (a standard key-management operation), the bridge's stored key becomes stale. Every call to verify an MPC signature will fail because the signature was produced under the new key but is checked against the old one. The result:

- **All withdrawal transactions are permanently unverifiable.**
- **All user nBTC/nZEC balances become unburnable** — users hold tokens they cannot redeem for underlying BTC/ZEC.
- **All bridge-held UTXOs are permanently locked** — the MPC signing pipeline cannot produce valid signatures that the bridge will accept.

This maps to: **Critical — Significant loss or permanent locking of user or protocol funds**, and **Medium — stuck bridge state requiring operator intervention** (a contract upgrade would be the only escape).

---

### Likelihood Explanation

NEAR chain signatures is an actively developed MPC service. Root public key rotation is a standard operational event for any MPC/threshold-signature system (key refresh, shard re-keying, security incident response). The bridge has no mechanism to survive such a rotation. The trigger is a normal infrastructure event, not an attack, making this a realistic operational risk rather than a theoretical one.

---

### Recommendation

Replace the one-time-only guard with a DAO-gated re-sync function that can be called at any time:

```rust
#[payable]
#[access_control_any(roles(Role::DAO))]
pub fn resync_chain_signatures_root_public_key(&mut self) -> Promise {
    assert_one_yocto();
    // Clear the stored key so the callback can overwrite it
    self.internal_mut_config().chain_signatures_root_public_key = None;
    self.sync_chain_signatures_root_public_key_promise()
}
```

Alternatively, add `chain_signatures_root_public_key` to `ConfigUpdate` with appropriate validation, or expose a dedicated DAO-only setter. The bridge should also add `chain_signatures_account_id` to `ConfigUpdate` for the same reason — it is equally frozen after initialization. [5](#0-4) 

---

### Proof of Concept

1. Bridge is deployed; DAO calls `sync_chain_signatures_root_public_key`. Key `K1` is stored.
2. NEAR chain-signatures service rotates to root key `K2` (normal operational event).
3. A user calls `ft_transfer_call` to initiate a withdrawal. The bridge calls `sign_btc_transaction`, which requests an MPC signature. The MPC service returns a signature under `K2`.
4. The bridge's signature verification checks the signature against stored key `K1` → verification fails → withdrawal reverts.
5. Every subsequent withdrawal attempt by every user fails identically.
6. DAO attempts to call `sync_chain_signatures_root_public_key` to update the key → `require!` panics with `"Already sync"`.
7. All user funds are permanently locked. The only escape is a full contract upgrade via the `Upgradable` mechanism, which itself requires a time-delayed governance process. [1](#0-0)

### Citations

**File:** contracts/satoshi-bridge/src/api/management.rs (L266-277)
```rust
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

**File:** contracts/satoshi-bridge/src/config.rs (L47-58)
```rust
pub struct Config {
    // The chain id: BitconMainnet/BitcoinTestnet/ZcashMainnet/ZcashTestnet etc
    pub chain: network::Chain,
    // The account id of btc light client contract
    pub btc_light_client_account_id: AccountId,
    // The account id of nbtc contract
    pub nbtc_account_id: AccountId,
    // The account id of chain signatures contract
    pub chain_signatures_account_id: AccountId,
    // The root public key of chain signatures contract
    pub chain_signatures_root_public_key: Option<PublicKey>,
    // The change address of BTC transaction
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

**File:** contracts/satoshi-bridge/src/config.rs (L265-302)
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
}
```

**File:** contracts/satoshi-bridge/src/lib.rs (L127-147)
```rust
pub struct ContractData {
    pub config: LazyOption<Config>,
    pub accounts: IterableMap<AccountId, VAccount>,
    pub utxos: IterableMap<String, VUTXO>,
    pub unavailable_utxos: IterableMap<String, VUTXO>,
    pub verified_deposit_utxo: LookupSet<String>,
    pub btc_pending_infos: IterableMap<String, VBTCPendingInfo>,
    pub rbf_txs: IterableMap<String, HashSet<String>>,
    pub relayer_white_list: IterableSet<AccountId>,
    pub extra_msg_relayer_white_list: IterableSet<AccountId>,
    pub post_action_receiver_id_white_list: IterableSet<AccountId>,
    pub post_action_msg_templates: IterableMap<AccountId, HashSet<String>>,
    pub pending_tx_limits: IterableMap<AccountId, u32>,
    pub lost_found: IterableMap<AccountId, u128>,
    pub acc_collected_protocol_fee: u128,
    pub cur_available_protocol_fee: u128,
    pub acc_claimed_protocol_fee: u128,
    pub cur_reserved_protocol_fee: u128,
    pub acc_protocol_fee_for_gas: u128,
    pub refund_requests: IterableMap<String, VRefundRequest>,
}
```
