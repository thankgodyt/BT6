### Title
No Method to Withdraw Accumulated NEAR Stuck in `satoshi-bridge` Contract - (File: contracts/satoshi-bridge/src/api/management.rs)

### Summary
The `satoshi-bridge` contract accumulates NEAR tokens from mandatory, non-refundable storage deposits paid by callers of `request_refund` and `execute_refund`. When storage is later freed (on `verify_refund_finalize`), the NEAR returns to the contract's own balance. There is no admin function to withdraw this accumulated NEAR. The only withdrawal method, `withdraw_protocol_fee`, exclusively transfers nBTC (NEP-141 tokens), not NEAR.

### Finding Description
Two public entry points require callers to attach NEAR:

**`request_refund`** — explicitly documented as non-refundable:

> "Requires an attached deposit of at least `required_balance_for_request_refund()`. The deposit is NOT refunded — it covers request storage and acts as an anti-spam fee." [1](#0-0) 

**`execute_refund`** — also requires an attached storage deposit: [2](#0-1) 

When `verify_refund_finalize_callback` removes the refund request from on-chain storage, the NEAR used for that storage slot is freed back to the contract's own balance: [3](#0-2) 

The only admin withdrawal function in `management.rs` is `withdraw_protocol_fee`, which calls `internal_withdraw_protocol_fee` — a cross-contract `ft_transfer` to the nBTC NEP-141 contract. It has no path to transfer NEAR: [4](#0-3) [5](#0-4) 

No other function in `management.rs` or anywhere in the production bridge surface transfers NEAR out of the contract to an admin account. [6](#0-5) 

### Impact Explanation
NEAR tokens paid as storage deposits by every `request_refund` and `execute_refund` caller accumulate permanently in the bridge contract with no recovery path. If the bridge is deprecated or paused indefinitely, all accumulated NEAR is irrecoverable by the DAO or any other role. This constitutes stuck protocol-level funds with no operator intervention path — matching the Medium impact class of "harmful smart-contract behavior without direct funds theft."

### Likelihood Explanation
Every refund lifecycle (which is a normal, documented user flow) contributes NEAR to the stuck balance. The `request_refund` deposit is explicitly non-refundable by design. Over the operational lifetime of the bridge, the accumulated amount grows monotonically. Likelihood is certain given normal bridge usage.

### Recommendation
Add a DAO-gated function to withdraw accumulated NEAR from the contract balance, analogous to `withdraw_protocol_fee` for nBTC. For example:

```rust
#[payable]
#[access_control_any(roles(Role::DAO))]
pub fn withdraw_near(&mut self, amount: Option<NearToken>, receiver_id: AccountId) -> Promise {
    assert_one_yocto();
    let amount = amount.unwrap_or_else(|| env::account_balance());
    Promise::new(receiver_id).transfer(amount)
}
```

This mirrors the pattern recommended in the original report (a `transferGas`-style function for the admin).

### Proof of Concept
1. User calls `request_refund(...)` attaching `required_balance_for_request_refund()` NEAR. The NEAR is kept by the contract; the docs confirm it is not refunded.
2. After the timelock, user calls `execute_refund(...)` attaching `required_balance_for_execute_refund()` NEAR. Again kept by the contract.
3. Relayer calls `verify_refund_finalize(...)`. `verify_refund_finalize_callback` removes the refund request from `data().refund_requests`, freeing the storage NEAR back to the contract's balance.
4. DAO attempts to recover the accumulated NEAR — no function exists. `withdraw_protocol_fee` only transfers nBTC. The NEAR is permanently stuck. [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L146-149)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_request_refund(),
            "Insufficient deposit for storage"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L202-205)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_execute_refund(),
            "Insufficient deposit for storage"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L459-494)
```rust
#[near]
impl Contract {
    #[private]
    pub fn verify_refund_finalize_callback(&mut self, tx_id: String) -> bool {
        let result_bytes = env::promise_result_checked(0, MAX_BOOL_RESULT)
            .expect("Call verify_transaction_inclusion failed");
        let is_valid = serde_json::from_slice::<bool>(&result_bytes)
            .expect("verify_transaction_inclusion return not bool");
        require!(is_valid, "verify_transaction_inclusion return false");

        let btc_pending_info = self.internal_unwrap_btc_pending_info(&tx_id).clone();
        btc_pending_info.assert_refund_pending_verify_tx();

        let account_id = btc_pending_info.account_id.clone();

        // A refund spends exactly one deposit UTXO, whose key is the refund request
        // key. More than one input would be abnormal for a refund.
        let utxo_storage_keys = btc_pending_info.get_psbt().get_utxo_storage_keys();
        require!(
            utxo_storage_keys.len() == 1,
            "refund transaction must spend exactly one input"
        );
        // Refund confirmed on-chain → drop the request so no further execute_refund
        // is possible. If it was already removed, this is harmlessly a no-op.
        self.data_mut()
            .refund_requests
            .remove(&utxo_storage_keys[0]);

        // Clean up: remove pending info
        self.internal_remove_btc_pending_info(&tx_id);
        self.internal_unwrap_mut_account(&account_id)
            .btc_pending_verify_list
            .remove(&tx_id);

        true
    }
```

**File:** contracts/satoshi-bridge/src/api/management.rs (L1-30)
```rust
use crate::{
    assert_one_yocto, env, near, require, AccessControllable, Account, AccountId, ConfigUpdate,
    Contract, ContractExt, HashSet, Promise, Role, U128,
};

use near_plugins::access_control_any;

#[near]
impl Contract {
    /// Withdraw a specified amount of protocol fee to the owner’s account.
    ///
    /// # Arguments
    ///
    /// * `amount` - Specify the amount to withdraw; if not specified, it will be the full amount.
    ///
    /// # Returns
    ///
    /// bool - Whether the Withdraw was successful.
    #[payable]
    #[access_control_any(roles(Role::DAO))]
    pub fn withdraw_protocol_fee(&mut self, amount: Option<U128>) -> Promise {
        assert_one_yocto();
        let total_protocol_fee = self.data().cur_available_protocol_fee;
        let amount = amount.map_or(total_protocol_fee, |v| v.0);
        require!(amount > 0 && amount <= total_protocol_fee, "Invalid amount");
        self.data_mut().cur_available_protocol_fee -= amount;
        self.data_mut().acc_claimed_protocol_fee += amount;
        self.internal_withdraw_protocol_fee(amount)
    }
}
```

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L11-21)
```rust
    pub fn internal_withdraw_protocol_fee(&self, amount: u128) -> Promise {
        ext_ft_core::ext(self.internal_config().nbtc_account_id.clone())
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .with_static_gas(GAS_FOR_TOKEN_TRANSFER)
            .ft_transfer(env::predecessor_account_id(), amount.into(), None)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_AFTER_TOKEN_TRANSFER)
                    .withdraw_protocol_fee_callback(amount.into()),
            )
    }
```
