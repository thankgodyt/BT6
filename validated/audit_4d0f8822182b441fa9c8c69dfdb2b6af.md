### Title
Missing Ownership Check in `internal_cancel_withdraw` Allows Any User to Cancel Another User's Pending Withdrawal — (File: `contracts/satoshi-bridge/src/rbf/cancel_withdraw.rs`)

---

### Summary

`internal_cancel_withdraw` accepts an `_account_id` parameter that is intentionally unused (Rust `_` prefix suppresses the warning). Unlike its sibling `internal_withdraw_rbf`, which enforces `account_id == original_tx.account_id`, the cancel path performs **no ownership check**. The only conditional access-control gate — a DAO role check — fires only when `excess_gas_fee > 0`. When the gas fee fits within the user's pre-paid `withdraw_fee`, the gate is skipped entirely, leaving the function callable by any NEAR account.

---

### Finding Description

`internal_withdraw_rbf` correctly guards the RBF path:

```rust
// contracts/satoshi-bridge/src/rbf/withdraw.rs  lines 43-46
require!(
    &original_tx_btc_pending_info.account_id == account_id,
    "Not allow"
);
``` [1](#0-0) 

`internal_cancel_withdraw` receives the same `account_id` argument but prefixes it with `_`, making it dead code:

```rust
// contracts/satoshi-bridge/src/rbf/cancel_withdraw.rs  lines 22-27
pub fn internal_cancel_withdraw(
    &mut self,
    _account_id: &AccountId,   // ← never read; no ownership check
    original_btc_pending_verify_id: String,
    ...
``` [2](#0-1) 

The only access-control check present is conditional:

```rust
// lines 57-61
if excess_gas_fee > 0 {
    require!(
        self.acl_has_role(Role::DAO.into(), predecessor_account_id),
        "gas fee exceeds the user's balance, only the owner is allowed to cancel"
    );
``` [3](#0-2) 

When `excess_gas_fee == 0` — i.e., the gas fee of the cancel transaction is ≤ `transfer_amount - withdraw_fee` — the branch is never entered and **any caller** passes through.

The `define_rbf_method!` macro that wraps this function passes the caller-supplied `account_id` into `internal_cancel_withdraw` (where it is ignored) and also inserts the new cancel-RBF pending ID into that caller-supplied account's `btc_pending_sign_ids`:

```rust
// contracts/satoshi-bridge/src/bitcoin_utils/contract_methods.rs  lines 27-36
let btc_pending_id = self.$internal_fn(
    &account_id,
    original_btc_pending_verify_id,
    new_psbt,
    predecessor_account_id,
);
self.internal_unwrap_mut_account(&account_id)
    .btc_pending_sign_ids
    .insert(btc_pending_id.clone());
``` [4](#0-3) 

The new `BTCPendingInfo` inherits `account_id` from the original transaction (the victim), not from the attacker:

```rust
// contracts/satoshi-bridge/src/rbf/mod.rs  lines 50-51
BTCPendingInfo {
    account_id: original_tx_btc_pending_info.account_id.clone(),
``` [5](#0-4) 

This creates an inconsistency: the cancel-RBF entry is owned by the victim but tracked in the attacker's signing queue.

---

### Impact Explanation

An attacker who waits for `max_btc_tx_pending_sec` to elapse on any victim's pending withdrawal can submit a cancel-RBF PSBT that redirects all UTXOs to the bridge's change address. The victim's nBTC was already burned at withdrawal initiation. Whether the bridge re-mints the nBTC on cancel confirmation depends on `verify_withdraw_v2` logic (not inspected here), but at minimum:

- The victim's withdrawal is forcibly aborted.
- The victim loses at least the gas fee embedded in the cancel transaction.
- The victim must re-initiate the withdrawal, paying fees again.
- The attacker can repeat this for every user whose withdrawal times out.

This matches the **Medium** allowed impact: *attacker-triggered temporary locking of bridged funds* and *bypass of bridge policies*.

---

### Likelihood Explanation

- No privileged role is required; any NEAR account can call the public cancel-withdraw entry point.
- The only precondition is that `max_btc_tx_pending_sec` has elapsed — a normal operational scenario for any congested withdrawal.
- The attacker must supply a valid cancel PSBT (all outputs to the bridge change address), which is straightforward to construct from the public pending-info state.
- The `excess_gas_fee == 0` condition is easily satisfied by choosing a cancel gas fee ≤ `transfer_amount - withdraw_fee`.

---

### Recommendation

Add an unconditional ownership check at the top of `internal_cancel_withdraw`, mirroring `internal_withdraw_rbf`:

```rust
require!(
    &original_tx_btc_pending_info.account_id == account_id
        || self.acl_has_role(Role::DAO.into(), predecessor_account_id.clone()),
    "Not allowed: caller is not the owner or DAO"
);
```

Alternatively, if cancel is intended to be DAO-only (as the wiki states), enforce the DAO role unconditionally and remove the `_account_id` parameter entirely.

---

### Proof of Concept

1. **Victim** calls `ft_transfer_call` → bridge burns nBTC, creates `BTCPendingInfo` with `account_id = victim`, state `PendingVerify`.
2. MPC signs the withdrawal; transaction is broadcast but remains unconfirmed past `max_btc_tx_pending_sec`.
3. **Attacker** constructs a cancel PSBT where all outputs go to the bridge change address with `gas_fee ≤ transfer_amount - withdraw_fee` (so `excess_gas_fee == 0`).
4. Attacker calls `cancel_withdraw_chain_specific(account_id=attacker, original_btc_pending_verify_id=victim_tx_id, output=[change_output])`.
5. `internal_cancel_withdraw` is entered; `_account_id` is ignored; the `excess_gas_fee == 0` branch skips the DAO check; the cancel-RBF `BTCPendingInfo` is created and stored.
6. MPC signs the cancel transaction; it is broadcast and confirmed.
7. Victim's withdrawal is permanently canceled; victim has lost their gas fee and must re-initiate.

### Citations

**File:** contracts/satoshi-bridge/src/rbf/withdraw.rs (L43-46)
```rust
        require!(
            &original_tx_btc_pending_info.account_id == account_id,
            "Not allow"
        );
```

**File:** contracts/satoshi-bridge/src/rbf/cancel_withdraw.rs (L22-27)
```rust
    pub fn internal_cancel_withdraw(
        &mut self,
        _account_id: &AccountId,
        original_btc_pending_verify_id: String,
        cancel_withdraw_rbf_psbt: PsbtWrapper,
        predecessor_account_id: AccountId,
```

**File:** contracts/satoshi-bridge/src/rbf/cancel_withdraw.rs (L55-61)
```rust
        let excess_gas_fee = gas_fee
            .saturating_sub(btc_pending_info.transfer_amount - btc_pending_info.withdraw_fee);
        if excess_gas_fee > 0 {
            require!(
                self.acl_has_role(Role::DAO.into(), predecessor_account_id),
                "gas fee exceeds the user's balance, only the owner is allowed to cancel"
            );
```

**File:** contracts/satoshi-bridge/src/bitcoin_utils/contract_methods.rs (L27-36)
```rust
            let btc_pending_id = self.$internal_fn(
                &account_id,
                original_btc_pending_verify_id,
                new_psbt,
                predecessor_account_id,
            );

            self.internal_unwrap_mut_account(&account_id)
                .btc_pending_sign_ids
                .insert(btc_pending_id.clone());
```

**File:** contracts/satoshi-bridge/src/rbf/mod.rs (L50-51)
```rust
    BTCPendingInfo {
        account_id: original_tx_btc_pending_info.account_id.clone(),
```
