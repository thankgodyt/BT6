### Title
`withdraw_rbf` Uses Caller's Account Instead of Pending-Info Owner, Enabling Unauthorized RBF on Any User's Withdrawal - (File: `contracts/satoshi-bridge/src/api/bridge.rs`)

---

### Summary

`withdraw_rbf` passes `env::predecessor_account_id()` as the `account_id` to `withdraw_rbf_chain_specific` without first verifying that the caller is the owner of `original_btc_pending_verify_id`. The privileged sibling function `cancel_withdraw` correctly fetches the owner from the stored `BTCPendingInfo`, but the unprivileged `withdraw_rbf` does not. Any NEAR account can therefore trigger an RBF operation on another user's pending withdrawal, with the RBF state recorded under the attacker's account rather than the original owner's.

---

### Finding Description

`withdraw_rbf` (bridge.rs, lines 259–274) is a public, unprivileged function:

```rust
pub fn withdraw_rbf(
    &mut self,
    original_btc_pending_verify_id: String,
    output: Vec<TxOut>,
    chain_specific_data: Option<ChainSpecificData>,
) {
    let account_id = env::predecessor_account_id();          // ← caller, not owner
    self.require_pending_sign_capacity(&account_id);
    self.withdraw_rbf_chain_specific(
        account_id,                                          // ← passed as owner
        original_btc_pending_verify_id,
        output,
        chain_specific_data,
    );
}
``` [1](#0-0) 

The privileged `cancel_withdraw` (lines 285–299) shows the correct pattern: it reads the true owner from the stored `BTCPendingInfo` before passing it downstream:

```rust
let user_account_id = self
    .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
    .account_id
    .clone();
self.require_pending_sign_capacity(&user_account_id);
self.cancel_withdraw_chain_specific(
    user_account_id,
    original_btc_pending_verify_id,
    ...
);
``` [2](#0-1) 

`BTCPendingInfo` carries an `account_id` field that records the true owner of the pending withdrawal. [3](#0-2)  The downstream `withdraw_rbf_chain_specific` uses the supplied `account_id` to create a new RBF `BTCPendingInfo` entry and insert it into the owner's `btc_pending_sign_ids` set — exactly as `create_btc_pending_info` does for normal withdrawals and `finalize_refund_with_psbt` does for refunds. [4](#0-3) [5](#0-4) 

Because `withdraw_rbf` passes the *caller's* account instead of the *owner's* account, the resulting RBF pending info is attributed to the attacker, not the legitimate user.

---

### Impact Explanation

An attacker who calls `withdraw_rbf` on a victim's pending withdrawal causes:

1. **Ownership mismatch**: The new RBF `BTCPendingInfo` is stored under the attacker's account. The victim's account has no record of the RBF transaction and cannot manage it (sign, verify, or cancel it).
2. **Stuck withdrawal**: The original pending withdrawal is superseded by the RBF transaction, but the victim has no handle to the RBF entry. The victim's funds (nBTC already transferred to the bridge) are locked until an operator intervenes.
3. **Capacity exhaustion**: `require_pending_sign_capacity` is checked against the *attacker's* account, not the victim's, so the attacker can repeatedly trigger RBFs on many victims' withdrawals without consuming their own capacity.

This matches the **Medium** impact: attacker-triggered temporary locking of bridged funds / stuck bridge state requiring operator intervention.

---

### Likelihood Explanation

`withdraw_rbf` is a public function with no access-control decorator and no ownership check. Any NEAR account can call it with any `original_btc_pending_verify_id` visible on-chain (all pending IDs are emitted as events). The only cost to the attacker is the 1 yoctoNEAR attached deposit required by `assert_one_yocto` — which is absent here — making this trivially cheap to exploit at scale. [6](#0-5) 

---

### Recommendation

Mirror the pattern used in `cancel_withdraw`: fetch the true owner from the stored `BTCPendingInfo` before passing it to `withdraw_rbf_chain_specific`, and verify that `env::predecessor_account_id()` matches that owner:

```rust
pub fn withdraw_rbf(...) {
    let pending_info = self.internal_unwrap_btc_pending_info(&original_btc_pending_verify_id);
    let account_id = pending_info.account_id.clone();
    require!(
        env::predecessor_account_id() == account_id,
        "Only the withdrawal owner can RBF"
    );
    self.require_pending_sign_capacity(&account_id);
    self.withdraw_rbf_chain_specific(account_id, original_btc_pending_verify_id, output, chain_specific_data);
}
```

---

### Proof of Concept

1. Alice calls `ft_transfer_call` → `ft_on_transfer` → a `BTCPendingInfo` is created with `account_id = alice`, `btc_pending_id = "txA"`. Alice's nBTC is now held by the bridge.
2. Attacker Bob observes the `GenerateBtcPendingInfo` event for `"txA"`.
3. Bob calls `withdraw_rbf("txA", <modified_output>, None)`.
4. Inside `withdraw_rbf`, `account_id = bob` (Bob's address). `withdraw_rbf_chain_specific(bob, "txA", ...)` creates a new RBF `BTCPendingInfo` under Bob's account.
5. Alice's original pending withdrawal is now superseded by the RBF transaction, but Alice has no record of the RBF entry and cannot call `verify_withdraw` or manage it.
6. Alice's nBTC remains locked in the bridge indefinitely until a DAO/Operator manually intervenes. [1](#0-0) [2](#0-1)

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L259-274)
```rust
    pub fn withdraw_rbf(
        &mut self,
        original_btc_pending_verify_id: String,
        output: Vec<TxOut>,
        chain_specific_data: Option<ChainSpecificData>,
    ) {
        let account_id = env::predecessor_account_id();
        self.require_pending_sign_capacity(&account_id);

        self.withdraw_rbf_chain_specific(
            account_id,
            original_btc_pending_verify_id,
            output,
            chain_specific_data,
        );
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L285-299)
```rust
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

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L1-5)
```rust
use std::borrow::{Borrow, BorrowMut};

use crate::{
    env, nano_to_sec, near, network, psbt_wrapper::PsbtWrapper, require, u128_dec_format,
    AccountId, Contract, SignatureResponse, WrappedTransaction, U128, VUTXO,
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L124-134)
```rust
        require!(
            self.data_mut()
                .btc_pending_infos
                .insert(btc_pending_id.clone(), btc_pending_info.into())
                .is_none(),
            "pending info already exist"
        );
        self.internal_unwrap_mut_account(&sender_id)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());
        Event::UtxoRemoved { utxo_storage_keys }.emit();
```

**File:** contracts/satoshi-bridge/src/refund.rs (L373-375)
```rust
        self.internal_unwrap_mut_account(&caller)
            .btc_pending_sign_ids
            .insert(btc_pending_id.clone());
```
