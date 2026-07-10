Based on my analysis of the codebase, I identified a clear authorization bypass analog in the `withdraw_rbf` function.

---

### Title
Unauthorized Caller Can Trigger RBF on Another User's Pending Withdrawal — (`contracts/satoshi-bridge/src/api/bridge.rs`)

### Summary
`withdraw_rbf` never verifies that the caller owns the `original_btc_pending_verify_id` it is asked to replace. Any unprivileged NEAR account can invoke it against a victim's pending withdrawal, disrupting or hijacking the victim's in-flight BTC transaction.

### Finding Description

`withdraw_rbf` is documented as the function by which **the user** accelerates their own withdrawal by increasing the gas fee:

```rust
// api/bridge.rs lines 258-274
pub fn withdraw_rbf(
    &mut self,
    original_btc_pending_verify_id: String,
    output: Vec<TxOut>,
    chain_specific_data: Option<ChainSpecificData>,
) {
    let account_id = env::predecessor_account_id();
    self.require_pending_sign_capacity(&account_id);   // ← checks CALLER's capacity

    self.withdraw_rbf_chain_specific(
        account_id,                          // ← caller, not the owner of the pending tx
        original_btc_pending_verify_id,      // ← any pending tx ID, no ownership check
        output,
        chain_specific_data,
    );
}
``` [1](#0-0) 

Every `BTCPendingInfo` carries an `account_id` field that records the true owner of the pending transaction:

```rust
// btc_pending_info.rs line 108
pub struct BTCPendingInfo {
    pub account_id: AccountId,   // ← the real owner
    ...
}
``` [2](#0-1) 

The function never performs a check equivalent to:
```rust
require!(btc_pending_info.account_id == env::predecessor_account_id(), "Not authorized");
```

Compare this with the **operator-only** `cancel_withdraw`, which correctly derives the owner from the pending info rather than from the caller:

```rust
// api/bridge.rs lines 287-291
let user_account_id = self
    .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
    .account_id
    .clone();
self.require_pending_sign_capacity(&user_account_id);
``` [3](#0-2) 

`withdraw_rbf` applies `require_pending_sign_capacity` to the **caller**, not to the owner of the pending transaction. This is the same class of bug as the MagicSea `_requireOnlyOperatorOrOwnerOf` issue: the authorization check is performed against the wrong identity, making it trivially bypassable.

### Impact Explanation

An attacker who calls `withdraw_rbf` with a victim's `original_btc_pending_verify_id` and attacker-controlled `output`:

1. Triggers creation of a new RBF transaction that replaces the victim's in-flight withdrawal in the Bitcoin mempool.
2. The new `BTCPendingInfo` is created under the **attacker's** `account_id`, removing the victim's control over the transaction lifecycle (signing, verification, cancellation).
3. The attacker supplies the `output` field, which governs the fee structure and change outputs of the replacement transaction. Depending on PSBT validation strictness in `withdraw_rbf_chain_specific` (not fully accessible for review), this may allow partial redirection of funds or at minimum permanently disrupts the victim's withdrawal, locking their nBTC in the bridge until operator intervention.

This maps to: **Medium — attacker-triggered temporary locking of bridged funds / bypass of bridge policies**.

### Likelihood Explanation

- `withdraw_rbf` is a public, unpermissioned function callable by any NEAR account.
- The only precondition is that the attacker has their own account registered and has pending sign capacity (default limit is 1, easily satisfied by a fresh account).
- The victim's `original_btc_pending_verify_id` is observable on-chain via view calls or events (`GenerateBtcPendingInfo`).
- No front-running is required; the attacker can act at any time while the victim's withdrawal is in the `PendingSign` stage.

### Recommendation

Add an ownership check at the start of `withdraw_rbf`, mirroring the pattern used in `cancel_withdraw`:

```rust
pub fn withdraw_rbf(
    &mut self,
    original_btc_pending_verify_id: String,
    output: Vec<TxOut>,
    chain_specific_data: Option<ChainSpecificData>,
) {
    let caller = env::predecessor_account_id();
    // Verify caller owns the pending transaction
    let owner = self
        .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
        .account_id
        .clone();
    require!(caller == owner, "Not authorized: caller does not own this pending transaction");
    self.require_pending_sign_capacity(&caller);
    self.withdraw_rbf_chain_specific(caller, original_btc_pending_verify_id, output, chain_specific_data);
}
```

### Proof of Concept

1. Alice calls `ft_transfer_call` → `ft_on_transfer` → `create_btc_pending_info`, creating a withdrawal with `btc_pending_id = "abc123"` owned by `alice.near`.
2. Bob (any NEAR account) observes the `GenerateBtcPendingInfo` event and learns `btc_pending_id = "abc123"`.
3. Bob calls `withdraw_rbf("abc123", [attacker_output], None)`.
4. `account_id = bob.near`; `require_pending_sign_capacity(&bob.near)` passes (Bob has no pending txs).
5. `withdraw_rbf_chain_specific(bob.near, "abc123", ...)` executes, creating a new RBF `BTCPendingInfo` owned by `bob.near` that replaces Alice's transaction.
6. Alice's original pending transaction is invalidated; she can no longer sign, verify, or cancel it. Her nBTC remains locked in the bridge.

### Citations

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L258-274)
```rust
    #[pause(except(roles(Role::DAO)))]
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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L287-291)
```rust
        let user_account_id = self
            .internal_unwrap_btc_pending_info(&original_btc_pending_verify_id)
            .account_id
            .clone();
        self.require_pending_sign_capacity(&user_account_id);
```

**File:** contracts/satoshi-bridge/src/btc_pending_info.rs (L107-110)
```rust
pub struct BTCPendingInfo {
    pub account_id: AccountId,
    pub btc_pending_id: String,
    #[serde(with = "u128_dec_format")]
```
