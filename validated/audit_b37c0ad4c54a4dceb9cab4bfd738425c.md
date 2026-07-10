### Title
Silent Token Retention in `safe_mint` When Recipient Account Is Unregistered — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

The `safe_mint` function in the nBTC contract mints tokens to the bridge's own account and then silently returns `U128(0)` — with no error, no event, and no lost-found entry — when the intended recipient has not registered a storage account in the token contract. The minted tokens accumulate in the bridge's balance untracked, the user receives nothing, and no signal is emitted to indicate the failure.

---

### Finding Description

`safe_mint` executes in two distinct steps:

**Step 1 — Unconditional mint to bridge:** [1](#0-0) 

`self.token.internal_deposit(&self.bridge_id, amount.into())` runs unconditionally, crediting `amount` nBTC to the bridge's own token balance before any check on the recipient.

**Step 2 — Silent early return when recipient is unregistered:** [2](#0-1) 

```rust
if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));
}
```

If the recipient has no storage registration, the function returns `U128(0)` immediately. No `require!` panic, no event, no `lost_found` entry, no rollback of the tokens already deposited to the bridge. The minted tokens remain silently in the bridge's balance with no record that they are owed to the user.

This is structurally identical to the reported `compute_emission_amount` pattern: a `min()`-style silent clamp that reduces the user's received amount to zero without any feedback. Here the "clamp" is the unregistered-account guard that zeroes the transfer while leaving the mint intact.

The `mint` function (the standard deposit path) avoids this by calling `mint_inner`, which auto-registers the account before depositing: [3](#0-2) 

`safe_mint` deliberately skips that auto-registration, making the silent-zero path reachable for any unregistered recipient.

---

### Impact Explanation

- The bridge mints `amount` nBTC to its own balance.
- The user receives **zero** nBTC.
- The minted tokens are not recorded in `lost_found` or any other recovery structure.
- No event is emitted; neither the user nor operators are notified.
- The user's BTC deposit is locked in the MPC-controlled address with no corresponding nBTC and no automated recovery path.
- Recovery requires manual operator intervention to identify the discrepancy and redistribute the bridge-held tokens.

**Impact class:** Medium — broken callback / stuck bridge state requiring operator intervention; potential for permanent user fund loss if the silent failure is not detected.

---

### Likelihood Explanation

Any user who triggers the `safe_mint` path (e.g., via a legacy or Near-Intents deposit flow) without having previously called `storage_deposit` on the nBTC contract will hit this branch. NEP-141 storage registration is a non-obvious prerequisite; new or automated users frequently omit it. The condition is reachable by any unprivileged account that initiates a deposit without pre-registering.

---

### Recommendation

Replace the silent early return with one of the following:

1. **Panic/revert:** `require!(self.token.accounts.get(&account_id).is_some(), "Recipient account not registered");` — placed *before* `internal_deposit`, so no tokens are minted if the recipient is unregistered.
2. **Lost-found tracking:** If silent continuation is required, record the minted amount in `self.data_mut().lost_found` so the user can reclaim it later, and emit an event.
3. **Auto-register:** Mirror `mint_inner` and register the account before depositing, eliminating the unregistered-account case entirely.

---

### Proof of Concept

1. User deposits BTC to the bridge-controlled address without calling `storage_deposit` on the nBTC contract.
2. A relayer submits the inclusion proof; the bridge verifies it and calls `safe_mint(user_account_id, amount, msg)` on the nBTC contract.
3. `safe_mint` executes `self.token.internal_deposit(&self.bridge_id, amount.into())` — `amount` nBTC is credited to the bridge.
4. `self.token.accounts.get(&user_account_id)` returns `None` (unregistered).
5. The function returns `PromiseOrValue::Value(U128(0))` — no transfer, no event, no lost-found entry.
6. The user holds 0 nBTC. Their BTC is locked. The bridge holds `amount` extra nBTC with no record of the debt.
7. The discrepancy is invisible on-chain until an operator manually audits bridge-held token balances against expected protocol fees. [4](#0-3)

### Citations

**File:** contracts/nbtc/src/lib.rs (L101-124)
```rust
    pub fn safe_mint(
        &mut self,
        account_id: AccountId,
        amount: U128,
        msg: Option<String>,
    ) -> PromiseOrValue<U128> {
        self.assert_bridge();
        require!(
            account_id != self.bridge_id,
            "safe_mint: account_id must not be the bridge"
        );
        self.token.internal_deposit(&self.bridge_id, amount.into());

        if self.token.accounts.get(&account_id).is_none() {
            return PromiseOrValue::Value(U128(0));
        }

        if let Some(msg) = msg {
            self.ft_transfer_call(account_id, amount, None, msg)
        } else {
            self.ft_transfer(account_id, amount, None);
            PromiseOrValue::Value(amount)
        }
    }
```

**File:** contracts/nbtc/src/lib.rs (L341-345)
```rust
    fn mint_inner(&mut self, account_id: &AccountId, amount: U128) {
        if self.token.accounts.get(account_id).is_none() {
            self.token.internal_register_account(account_id);
        }
        self.token.internal_deposit(account_id, amount.into());
```
