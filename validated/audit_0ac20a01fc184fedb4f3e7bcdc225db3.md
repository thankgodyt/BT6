### Title
Operator's `cancel_withdraw` Can Be DoSed by User Filling Their Pending Sign Capacity — (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

The `cancel_withdraw` function, restricted to DAO/Operator roles, checks `require_pending_sign_capacity` against the *withdrawal initiator's* account rather than the operator's. A user can intentionally fill their own pending sign capacity by initiating multiple withdrawals, blocking the operator from canceling their stuck withdrawal until the DAO manually increases the user's per-account limit.

---

### Finding Description

In `contracts/satoshi-bridge/src/api/bridge.rs`, `cancel_withdraw` is the operator's mechanism to RBF-cancel a withdrawal that has not confirmed within `max_btc_tx_pending_sec`. It creates a new `WithdrawCancelRbf` `BTCPendingInfo` entry in `PendingSign` state, which is added to the *user's* `btc_pending_sign_ids`. The capacity guard is therefore applied to the user's account: [1](#0-0) 

```rust
#[payable]
#[access_control_any(roles(Role::DAO, Role::Operator))]
#[pause(except(roles(Role::DAO)))]
pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
    assert_one_yocto();
    let user_account_id = self
        .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
        .account_id
        .clone();
    self.require_pending_sign_capacity(&user_account_id);   // ← checked on user, not operator
    self.cancel_withdraw_chain_specific(
        user_account_id,
        original_btc_pending_verify_id,
        output,
        None,
    );
}
```

The cancel RBF is constructed in `internal_cancel_withdraw` and stored as a new `WithdrawCancelRbf` entry in `PendingSign` state under the user's account: [2](#0-1) 

Because the new pending info is attributed to the user, the capacity check is logically necessary — but it is user-controllable. A user can fill their own `btc_pending_sign_ids` up to the per-account limit (set via `set_pending_tx_limit` in management.rs) by initiating multiple withdrawals or RBF transactions, then allow one withdrawal to become stuck in `PendingVerify`. When the operator calls `cancel_withdraw`, `require_pending_sign_capacity` fails and the cancel is blocked.

The same structural pattern exists in `cancel_active_utxo_management`: [3](#0-2) 

The per-account limit is stored in `pending_tx_limits`: [4](#0-3) 

---

### Impact Explanation

When the operator cannot cancel a stuck withdrawal:

- The BTC UTXOs locked in the pending withdrawal remain inaccessible to the protocol indefinitely.
- The user's nBTC was already burned at withdrawal initiation — that burn is irreversible.
- The bridge is in a stuck state until the DAO manually calls `set_pending_tx_limit` to raise the user's limit and then retries the cancel.

This matches **Medium — attacker-triggered temporary locking of bridged funds** and **stuck bridge state requiring operator intervention**.

---

### Likelihood Explanation

The attack requires the user to:

1. Have enough nBTC to initiate multiple withdrawals (W1 through WN, where N equals their pending sign limit).
2. Allow W1 to enter `PendingVerify` (MPC-signed) while keeping W2…WN in `PendingSign` (not yet signed), filling `btc_pending_sign_ids`.
3. Allow W1 to remain unconfirmed past `max_btc_tx_pending_sec`.

A user has a concrete motivation: they may believe their original BTC transaction will eventually confirm and want to prevent the cancel RBF from double-spending it. The cost is locking their own nBTC in the additional withdrawals, but those withdrawals can later be processed normally. The attack is straightforward for any user with sufficient nBTC balance.

---

### Recommendation

Decouple the cancel RBF's pending-sign accounting from the user's capacity limit. Options include:

1. Track the `WithdrawCancelRbf` pending info under the **operator's** account rather than the user's, so the capacity check applies to the operator (who is trusted and not subject to user-controlled DoS).
2. Exempt operator-initiated cancel entries from the per-account capacity check entirely, since the cancel is a privileged administrative action.
3. Add a separate, DAO-controlled bypass flag to `cancel_withdraw` that skips the capacity check when the caller is DAO/Operator.

---

### Proof of Concept

1. Alice initiates withdrawal W1 via `ft_transfer_call` → nBTC burned, W1 enters `PendingSign`.
2. Relayer calls `sign_btc_transaction` for W1 → W1 moves to `PendingVerify`, removed from `btc_pending_sign_ids`.
3. Alice initiates withdrawals W2, W3, …, WN (N = her pending sign limit) → `btc_pending_sign_ids` is now full.
4. W1 remains unconfirmed on Bitcoin past `max_btc_tx_pending_sec`.
5. Operator calls `cancel_withdraw(W1_pending_verify_id, output)`.
6. `require_pending_sign_capacity(&alice)` panics — Alice's `btc_pending_sign_ids` is at capacity.
7. W1's BTC UTXOs remain locked; the operator cannot cancel.
8. Resolution requires DAO to call `set_pending_tx_limit(alice, higher_limit)` before the cancel can proceed. [5](#0-4) [6](#0-5)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L282-299)
```rust
    #[payable]
    #[access_control_any(roles(Role::DAO, Role::Operator))]
    #[pause(except(roles(Role::DAO)))]
    pub fn cancel_withdraw(&mut self, original_btc_pending_verify_id: String, output: Vec<TxOut>) {
        assert_one_yocto();
        let user_account_id = self
            .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
            .account_id
            .clone();
        self.require_pending_sign_capacity(&user_account_id);

        self.cancel_withdraw_chain_specific(
            user_account_id,
            original_btc_pending_verify_id,
            output,
            None,
        );
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L408-428)
```rust
    #[payable]
    #[access_control_any(roles(Role::DAO, Role::Operator))]
    #[pause(except(roles(Role::DAO)))]
    pub fn cancel_active_utxo_management(
        &mut self,
        original_btc_pending_verify_id: String,
        output: Vec<TxOut>,
    ) {
        assert_one_yocto();
        let user_account_id = self
            .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
            .account_id
            .clone();
        self.require_pending_sign_capacity(&user_account_id);
        self.cancel_active_utxo_management_chain_specific(
            user_account_id,
            original_btc_pending_verify_id,
            output,
            None,
        );
    }
```

**File:** contracts/satoshi-bridge/src/rbf/cancel_withdraw.rs (L39-76)
```rust
        let mut btc_pending_info = init_rbf_btc_pending_info(
            original_tx_btc_pending_info,
            PendingInfoState::WithdrawCancelRbf(RbfState {
                stage: PendingInfoStage::PendingSign,
                original_tx_id: original_btc_pending_verify_id.clone(),
            }),
        );
        let (actual_received_amount, gas_fee) = self.check_cancel_withdraw_rbf_psbt_valid(
            original_tx_btc_pending_info,
            &cancel_withdraw_rbf_psbt,
        );

        btc_pending_info.gas_fee = gas_fee;
        btc_pending_info.burn_amount = gas_fee;
        btc_pending_info.actual_received_amount = actual_received_amount;
        Self::check_withdraw_chain_specific(original_tx_btc_pending_info, gas_fee);
        let excess_gas_fee = gas_fee
            .saturating_sub(btc_pending_info.transfer_amount - btc_pending_info.withdraw_fee);
        if excess_gas_fee > 0 {
            require!(
                self.acl_has_role(Role::DAO.into(), predecessor_account_id),
                "gas fee exceeds the user's balance, only the owner is allowed to cancel"
            );
            require!(
                self.data().cur_available_protocol_fee >= excess_gas_fee,
                "Insufficient protocol fee"
            );
            self.data_mut().cur_available_protocol_fee -= excess_gas_fee;
            self.data_mut().cur_reserved_protocol_fee += excess_gas_fee;
        }
        self.internal_unwrap_mut_btc_pending_info(&original_btc_pending_verify_id)
            .do_cancel(gas_fee, excess_gas_fee);
        self.set_rbf_pending_info(
            &original_btc_pending_verify_id,
            btc_pending_info,
            cancel_withdraw_rbf_psbt,
            true,
        )
```

**File:** contracts/satoshi-bridge/src/lib.rs (L139-139)
```rust
    pub pending_tx_limits: IterableMap<AccountId, u32>,
```

**File:** contracts/satoshi-bridge/src/api/management.rs (L190-205)
```rust
    #[payable]
    #[access_control_any(roles(Role::DAO))]
    pub fn set_pending_tx_limit(&mut self, account_id: AccountId, max_pending: Option<u32>) {
        assert_one_yocto();
        if let Some(max_pending) = max_pending {
            require!(max_pending >= 1, "Invalid max_pending value");
            self.data_mut()
                .pending_tx_limits
                .insert(account_id, max_pending);
        } else {
            let prev = self.data_mut().pending_tx_limits.remove(&account_id);
            require!(
                prev.is_some(),
                format!("Invalid account_id: {}", account_id)
            );
        }
```
