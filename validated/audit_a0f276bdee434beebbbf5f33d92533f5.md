### Title
Missing NEAR Recovery Function Allows Excess Attached Deposits to Become Permanently Stuck in satoshi-bridge - (File: contracts/satoshi-bridge/src/api/bridge.rs)

---

### Summary

The `satoshi-bridge` contract exposes multiple `#[payable]` public functions that require a minimum NEAR deposit for storage but do not refund any excess above that minimum. Because no sweep or NEAR-recovery function exists anywhere in the contract, any NEAR beyond the exact required amount — or any NEAR accidentally sent to the contract — is permanently locked with no on-chain recovery path.

---

### Finding Description

Two publicly reachable entry points accept NEAR deposits with only a lower-bound check:

**`request_refund`** (bridge.rs line 508–535):
```rust
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn request_refund(...) -> Promise {
    ...
}
```
The internal implementation enforces only a minimum:
```rust
require!(
    env::attached_deposit() >= self.required_balance_for_request_refund(),
    "Insufficient deposit for storage"
);
``` [1](#0-0) 

Any NEAR attached above `required_balance_for_request_refund()` is silently absorbed into the contract balance and never returned to the caller.

**`execute_refund`** (bridge.rs line 580–589):
```rust
#[payable]
#[pause(except(roles(Role::DAO)))]
pub fn execute_refund(...) -> PromiseOrValue<()> {
    let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
    ...
}
``` [2](#0-1) 

`resolve_execute_refund_timelock` again only checks a minimum:
```rust
require!(
    env::attached_deposit() >= self.required_balance_for_execute_refund(),
    "Insufficient deposit for storage"
);
``` [3](#0-2) 

**No sweep/recovery function exists.** The entire management API (`management.rs`) provides only `withdraw_protocol_fee`, which withdraws nBTC-denominated protocol fees — it has no mechanism to recover stuck NEAR tokens: [4](#0-3) 

Additionally, `verify_deposit_v2` is `#[payable]` and for safe-deposit paths requires the caller to attach NEAR for token storage: [5](#0-4) 

If a downstream cross-contract call in that flow fails and NEAR is refunded back to the bridge contract, it similarly has no recovery path.

---

### Impact Explanation

Any NEAR attached in excess of the required minimum to `request_refund` or `execute_refund` is permanently locked in the contract. There is no DAO-callable sweep function, no NEAR withdrawal function, and no mechanism for the protocol to recover these funds. Over time, as users over-attach NEAR (a common pattern when callers are unsure of the exact required amount), the contract accumulates irrecoverable NEAR.

**Impact class: Low** — Publicly reachable stuck-state in production bridge paths without direct theft of bridged BTC/nBTC.

---

### Likelihood Explanation

Any unprivileged user calling `request_refund` or `execute_refund` who attaches more NEAR than the exact minimum will trigger this. Wallets and dApps commonly attach a safe margin above the minimum to avoid rejection, making this a realistic and recurring scenario.

---

### Recommendation

Add a DAO-gated NEAR sweep function analogous to the `sweep()` fix described in the referenced report:

```rust
#[payable]
#[access_control_any(roles(Role::DAO))]
pub fn sweep_near(&mut self, amount: Option<NearToken>, receiver_id: AccountId) -> Promise {
    assert_one_yocto();
    let amount = amount.unwrap_or_else(|| env::account_balance());
    Promise::new(receiver_id).transfer(amount)
}
```

Additionally, consider refunding excess attached deposits at the end of `request_refund` and `execute_refund` by computing `env::attached_deposit() - required` and returning the difference via `Promise::new(env::predecessor_account_id()).transfer(excess)`.

---

### Proof of Concept

1. User calls `request_refund(...)` and attaches `required_balance_for_request_refund() + 1_000_000_000_000_000_000_000_000` yoctoNEAR (1 extra NEAR as margin).
2. The check at `refund.rs:146–149` passes (deposit ≥ minimum).
3. No code in `request_refund` or its callback `request_refund_callback` returns the excess to the caller.
4. The 1 extra NEAR is now part of the contract's balance.
5. No function in `management.rs` or anywhere else in the contract allows the DAO or any account to recover this NEAR.
6. The NEAR is permanently stuck. [6](#0-5) [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/refund.rs (L146-149)
```rust
        require!(
            env::attached_deposit() >= self.required_balance_for_request_refund(),
            "Insufficient deposit for storage"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L201-205)
```rust
    pub(crate) fn resolve_execute_refund_timelock(&self, utxo_storage_key: &str) -> u64 {
        require!(
            env::attached_deposit() >= self.required_balance_for_execute_refund(),
            "Insufficient deposit for storage"
        );
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L70-102)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn verify_deposit_v2(
        &mut self,
        deposit_msg: DepositMsg,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
    ) -> Promise {
        let coinbase_proof = Some((proof.coinbase_tx_id, proof.coinbase_merkle_proof));
        if deposit_msg.safe_deposit.is_some() {
            self.internal_safe_verify_deposit_entry(
                deposit_msg,
                tx_bytes.0,
                vout,
                proof.tx_block_blockhash,
                proof.tx_index,
                proof.merkle_proof,
                coinbase_proof,
            )
        } else {
            self.internal_verify_deposit_entry(
                deposit_msg,
                tx_bytes.0,
                vout,
                proof.tx_block_blockhash,
                proof.tx_index,
                proof.merkle_proof,
                coinbase_proof,
            )
        }
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L508-535)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn request_refund(
        &mut self,
        deposit_msg: DepositMsg,
        refund_address: String,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
        gas_fee: Option<U128>,
    ) -> Promise {
        if gas_fee.is_some() {
            let caller = env::predecessor_account_id();
            require!(
                self.acl_has_role(Role::DAO.into(), caller.clone())
                    || self.acl_has_role(Role::Operator.into(), caller),
                "Only DAO or Operator can specify custom gas_fee"
            );
        }
        self.internal_request_refund(
            deposit_msg,
            refund_address,
            tx_bytes,
            vout,
            proof,
            gas_fee.map(|v| v.0),
        )
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L580-589)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn execute_refund(
        &mut self,
        utxo_storage_key: String,
        chain_specific_data: Option<ChainSpecificData>,
    ) -> PromiseOrValue<()> {
        let timelock_sec = self.resolve_execute_refund_timelock(&utxo_storage_key);
        self.internal_execute_refund(utxo_storage_key, timelock_sec, chain_specific_data)
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
