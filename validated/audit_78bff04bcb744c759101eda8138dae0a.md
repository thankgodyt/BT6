### Title
Missing `chain_signatures_account_id` Update Path in `ConfigUpdate` Permanently Bricks Withdrawals if MPC Contract Migrates - (File: contracts/satoshi-bridge/src/config.rs)

---

### Summary

The `ConfigUpdate` struct, which is the only mechanism for the DAO to update live configuration, omits `chain_signatures_account_id`. If the NEAR Chain Signatures (MPC) contract migrates to a new address — a realistic operational event — the bridge has no on-chain path to point to the new contract. All withdrawal signing calls will permanently fail, locking every user's nBTC on NEAR with no redemption path.

---

### Finding Description

The `Config` struct stores three critical external contract IDs: [1](#0-0) 

The `ConfigUpdate` struct, used by the DAO-gated `update_config` function, exposes update fields for `btc_light_client_account_id` and `nbtc_account_id`, but **completely omits** `chain_signatures_account_id`: [2](#0-1) 

The `apply` method confirms the omission — `chain_signatures_account_id` is never passed through `set_if_some!`: [3](#0-2) 

The only management function touching the chain signatures contract is `sync_chain_signatures_root_public_key`, which is additionally guarded to run **exactly once** and can never be re-invoked: [4](#0-3) 

This means both the contract address (`chain_signatures_account_id`) and the root public key (`chain_signatures_root_public_key`) are permanently frozen after initialization. There is no privileged or unprivileged path to update either value post-deployment.

The `chain_signatures_account_id` is used directly in cross-contract calls during the MPC signing step of every withdrawal: [5](#0-4) 

---

### Impact Explanation

If the NEAR Chain Signatures contract migrates (a documented operational reality for MPC infrastructure), all calls to `sign_btc_transaction` will target a stale or non-existent contract. Every withdrawal initiated after the migration will fail at the MPC signing step. Users holding nBTC cannot redeem their tokens for BTC. The bridge enters a permanently stuck withdrawal state with no on-chain recovery path — the DAO cannot fix it without a full contract upgrade and migration. This constitutes **permanent locking of user funds** and a **stuck bridge state requiring operator intervention**.

---

### Likelihood Explanation

NEAR's Chain Signatures service is an actively evolving MPC protocol. Contract migrations and address changes are a normal part of its lifecycle. The bridge already acknowledges this by storing the address as a configurable field rather than a compile-time constant, but then fails to provide the update mechanism. The omission is a straightforward oversight in the `ConfigUpdate` struct.

---

### Recommendation

Add `chain_signatures_account_id` and a re-sync path for `chain_signatures_root_public_key` to `ConfigUpdate`:

```rust
// In ConfigUpdate struct (config.rs)
pub chain_signatures_account_id: Option<AccountId>,
pub chain_signatures_root_public_key: Option<PublicKey>,

// In ConfigUpdate::apply
set_if_some!(chain_signatures_account_id);
set_if_some!(chain_signatures_root_public_key);
```

Remove the `is_none()` guard from `sync_chain_signatures_root_public_key` so it can be re-invoked after a migration, or expose a direct setter for the root public key in `ConfigUpdate`. [6](#0-5) 

---

### Proof of Concept

1. Bridge is deployed with `chain_signatures_account_id = "v1.chain-signatures.near"`.
2. NEAR Chain Signatures migrates to `"v2.chain-signatures.near"`.
3. DAO calls `update_config` with any `ConfigUpdate` — `chain_signatures_account_id` is not a field, so it cannot be changed.
4. Any user calls `ft_transfer_call` on nBTC to initiate a withdrawal.
5. Bridge constructs the PSBT and calls `sign` on `"v1.chain-signatures.near"` — the old address.
6. The cross-contract call fails (contract no longer exists or no longer accepts the call).
7. The withdrawal callback handles the failure, but the user's nBTC has already been debited and the UTXO is locked in `unavailable_utxos`.
8. The bridge is stuck: no withdrawal can ever succeed, and there is no DAO function to update the MPC contract address. [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/config.rs (L51-55)
```rust
    pub btc_light_client_account_id: AccountId,
    // The account id of nbtc contract
    pub nbtc_account_id: AccountId,
    // The account id of chain signatures contract
    pub chain_signatures_account_id: AccountId,
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

**File:** contracts/satoshi-bridge/src/api/management.rs (L279-284)
```rust
    #[payable]
    #[access_control_any(roles(Role::DAO))]
    pub fn update_config(&mut self, update: ConfigUpdate) {
        assert_one_yocto();
        update.apply(self.internal_mut_config());
    }
```

**File:** contracts/satoshi-bridge/src/chain_signature.rs (L1-2)
```rust
use crate::{
    env, ext_contract, nano_to_sec, near, require, serde_json, AccountId, Contract, ContractExt,
```
