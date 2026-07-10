### Title
Tokens Minted to Bridge Account Are Permanently Stuck When Recipient Is Unregistered in `safe_mint` — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

The `safe_mint` function in the nBTC token contract unconditionally mints the full deposit amount to the bridge's own account (`bridge_id`) **before** checking whether the intended recipient is registered. If the recipient is unregistered, the function returns `U128(0)` and exits, leaving the minted nBTC permanently stranded in the bridge's own token balance with no on-chain recovery path.

---

### Finding Description

In `contracts/nbtc/src/lib.rs`, `safe_mint` executes in this order:

```rust
// Step 1 — tokens are minted to the bridge's own account (irreversible)
self.token.internal_deposit(&self.bridge_id, amount.into());

// Step 2 — only NOW is registration checked
if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));   // ← early exit; tokens already minted
}
``` [1](#0-0) 

The registration check at line 114 is the analog of the `token0()` heuristic in the external report: it is a binary gate that silently rejects a valid recipient. Because `internal_deposit` at line 112 has already credited `bridge_id`, the minted supply exists on-chain but is owned by the bridge contract, not the depositing user.

There is no function in the nBTC contract that lets the bridge (or anyone else) reclaim or redirect these stranded tokens back to the rightful owner. The `burn` function withdraws from `bridge_id`'s balance:

```rust
self.token.internal_withdraw(&self.bridge_id, burn_amount.into());
``` [2](#0-1) 

…but burning them destroys supply without releasing BTC to the user, compounding the accounting error.

---

### Impact Explanation

A user who deposits BTC to the bridge without first registering their account in the nBTC token contract will have their deposit verified and processed on-chain, but will receive **zero nBTC**. The minted tokens accumulate in `bridge_id`'s balance. Over time this inflates the bridge's nBTC balance beyond what it legitimately holds for in-flight withdrawals, creating a backed-supply discrepancy. The user's BTC is locked in the bridge's Bitcoin address with no corresponding nBTC claim and no on-chain mechanism to recover it. This matches the **Medium–Critical** impact band: significant loss of user funds and a broken callback/rollback path requiring operator intervention.

---

### Likelihood Explanation

Any user who calls the bridge's deposit flow without having previously called `storage_deposit` on the nBTC contract will trigger this. NEAR's NEP-141 storage registration is a separate, non-obvious step that new users routinely omit. No special privilege or attacker knowledge is required — the trigger is simply the absence of a prior `storage_deposit` call, which is a realistic and common condition.

---

### Recommendation

Invert the order of operations: **check registration before minting**. If the recipient is unregistered, either auto-register them (as `mint_inner` already does) or revert the entire call without touching `bridge_id`'s balance.

```rust
// Correct order
if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));  // exit before any mint
}
self.token.internal_deposit(&self.bridge_id, amount.into());
```

Alternatively, align `safe_mint` with `mint_inner`, which already auto-registers unregistered accounts: [3](#0-2) 

---

### Proof of Concept

1. User deposits BTC to the bridge's deposit address derived from their NEAR account `alice.near`.
2. `alice.near` has **not** called `storage_deposit` on the nBTC contract.
3. The bridge verifies the BTC transaction and calls `safe_mint(alice.near, 100_000, None)`.
4. `internal_deposit(&bridge_id, 100_000)` executes — 100 000 nBTC are minted to `bridge_id`. [4](#0-3) 
5. `accounts.get(&alice.near).is_none()` returns `true`. [5](#0-4) 
6. `safe_mint` returns `U128(0)`. Alice receives **zero** nBTC.
7. The 100 000 nBTC remain in `bridge_id`'s balance. No on-chain function exists to return them to Alice or to release her BTC. The tokens are permanently stuck.

### Citations

**File:** contracts/nbtc/src/lib.rs (L112-116)
```rust
        self.token.internal_deposit(&self.bridge_id, amount.into());

        if self.token.accounts.get(&account_id).is_none() {
            return PromiseOrValue::Value(U128(0));
        }
```

**File:** contracts/nbtc/src/lib.rs (L158-159)
```rust
        self.token
            .internal_withdraw(&self.bridge_id, burn_amount.into());
```

**File:** contracts/nbtc/src/lib.rs (L341-345)
```rust
    fn mint_inner(&mut self, account_id: &AccountId, amount: U128) {
        if self.token.accounts.get(account_id).is_none() {
            self.token.internal_register_account(account_id);
        }
        self.token.internal_deposit(account_id, amount.into());
```
