### Title
Mutable `nbtc_account_id` in `update_config` Permanently Locks In-Flight Withdrawal Funds - (File: `contracts/satoshi-bridge/src/config.rs`)

---

### Summary

`ConfigUpdate` exposes `nbtc_account_id` as an updatable field, allowing the DAO to silently redirect all future nBTC burn calls to a new token contract. Any withdrawal that was initiated (nBTC already transferred to the bridge on the **old** contract) but not yet finalized will have its burn call routed to the **new** contract, where the bridge holds no balance. The burn fails, the `BTCPendingInfo` is left in a permanently unresolvable state, and the user's nBTC is locked in the bridge's balance on the old contract with no recovery path.

---

### Finding Description

**Step 1 – The mutable reference.**

`ConfigUpdate` in `config.rs` includes `nbtc_account_id` as an optional field: [1](#0-0) 

`ConfigUpdate::apply()` unconditionally overwrites the live config value when the field is `Some`: [2](#0-1) 

The DAO can trigger this at any time via `update_config`: [3](#0-2) 

**Step 2 – How withdrawals depend on `nbtc_account_id`.**

When a user initiates a withdrawal, they call `ft_transfer_call` on the **current** nBTC contract. The bridge receives the tokens and records a `BTCPendingInfo` with `burn_amount`. Later, when `verify_withdraw` is called, `verify_withdraw_burn_promise` reads `nbtc_account_id` from the **live** config and issues the burn cross-contract call: [4](#0-3) 

**Step 3 – The stuck-state on address change.**

If the DAO calls `update_config` with a new `nbtc_account_id` between the user's `ft_transfer_call` and the relayer's `verify_withdraw`:

- The bridge's nBTC balance exists on the **old** contract.
- `verify_withdraw_burn_promise` calls `burn()` on the **new** contract.
- The new contract has no record of the bridge holding any tokens; the call fails.
- `verify_withdraw_burn_callback` handles the failure by calling `to_pending_verify_stage()`, keeping the `BTCPendingInfo` alive but permanently unresolvable: [5](#0-4) 

The user's nBTC is now locked in the bridge's balance on the old contract. There is no function in the bridge to recover tokens from a superseded nBTC contract address.

---

### Impact Explanation

**Permanent locking of user funds.** Every in-flight withdrawal at the moment of the `nbtc_account_id` change becomes unresolvable. The nBTC tokens are held by the bridge on the old contract but the bridge can only call `burn` on the new contract. No recovery function exists. This matches: *"Critical. Significant loss, theft, destruction, or permanent locking of user or protocol funds."*

---

### Likelihood Explanation

The DAO must call `update_config` with a new `nbtc_account_id`. This is a legitimate governance action (e.g., during a token migration), not a malicious one. The bridge has a `migrate_to_new_token` path, suggesting token migrations are anticipated. A DAO that changes `nbtc_account_id` without first draining all pending withdrawals will silently lock every in-flight withdrawal. Because the bridge is always-on and withdrawals are multi-step async operations, there will almost always be at least one pending withdrawal during any migration window.

---

### Recommendation

1. **Remove `nbtc_account_id` from `ConfigUpdate`** entirely, mirroring the fix recommended in the reference report ("remove the option to change … altogether"). Token migrations should be handled exclusively through the dedicated `migrate_to_new_token` path, which can be designed to drain pending state first.
2. If updatability must be retained, **add a guard** that panics if `btc_pending_infos` contains any entry with a non-zero `burn_amount` before allowing the `nbtc_account_id` change.

---

### Proof of Concept

1. User calls `ft_transfer_call(bridge, 1_000_000, withdraw_msg)` on `nbtc_v1.near`. Bridge receives 1 000 000 nBTC and creates `BTCPendingInfo { burn_amount: 990_000, … }`.
2. DAO calls `update_config({ nbtc_account_id: "nbtc_v2.near" })`.
3. Relayer calls `verify_withdraw_v2(tx_id, proof)`. Bridge calls `nbtc_v2.near.burn(user, 990_000, …)`.
4. `nbtc_v2.near` has no record of the bridge holding any tokens → call fails.
5. `verify_withdraw_burn_callback` receives `is_promise_success() == false`, calls `to_pending_verify_stage()`.
6. `BTCPendingInfo` is stuck in `PendingVerify`; the 990 000 nBTC remain locked in the bridge's balance on `nbtc_v1.near` with no callable path to recover them.

### Citations

**File:** contracts/satoshi-bridge/src/config.rs (L226-228)
```rust
    pub btc_light_client_account_id: Option<AccountId>,
    pub nbtc_account_id: Option<AccountId>,
    pub confirmations_delta: Option<u8>,
```

**File:** contracts/satoshi-bridge/src/config.rs (L266-275)
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
```

**File:** contracts/satoshi-bridge/src/api/management.rs (L281-284)
```rust
    pub fn update_config(&mut self, update: ConfigUpdate) {
        assert_one_yocto();
        update.apply(self.internal_mut_config());
    }
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L11-30)
```rust
    pub fn verify_withdraw_burn_promise(&self, tx_id: String) -> Promise {
        let btc_pending_info = self.internal_unwrap_btc_pending_info(&tx_id);
        let config = self.internal_config();
        let (protocol_fee, relayer_fee) = config
            .withdraw_bridge_fee
            .get_protocol_and_relayer_fee(btc_pending_info.withdraw_fee);
        ext_nbtc::ext(config.nbtc_account_id.clone())
            .with_static_gas(GAS_FOR_BURN_CALL)
            .burn(
                btc_pending_info.account_id.clone(),
                btc_pending_info.burn_amount.into(),
                env::signer_account_id(),
                relayer_fee.into(),
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_WITHDRAW_BURN_CALL_BACK)
                    .verify_withdraw_burn_callback(tx_id, protocol_fee.into(), relayer_fee.into()),
            )
    }
```

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L149-154)
```rust
        } else {
            self.internal_unwrap_mut_btc_pending_info(&tx_id)
                .to_pending_verify_stage();
        }
        burn_event.emit();
        is_success
```
