### Title
`safe_mint` Silently Inflates Bridge nBTC Supply on Unregistered Recipient, Permanently Locking User BTC — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

The `safe_mint` function in the nBTC token contract mints nBTC tokens to the bridge's own account (`bridge_id`) before checking whether the intended recipient is registered. When the recipient is unregistered, the function returns `U128(0)` and exits — leaving the freshly minted nBTC stranded in the bridge's balance with no recovery path for the user whose BTC is now locked.

---

### Finding Description

In `contracts/nbtc/src/lib.rs`, `safe_mint` executes in this order:

```rust
// Step 1 — tokens are minted to the bridge's own balance unconditionally
self.token.internal_deposit(&self.bridge_id, amount.into());

// Step 2 — only now is registration checked
if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));   // silent early return
}
``` [1](#0-0) 

When the recipient account is not registered on the nBTC contract:

1. `internal_deposit` increases `bridge_id`'s nBTC balance and the global total supply.
2. The function returns `U128(0)` — no transfer to the user, no `lost_found` entry, no event.
3. The minted nBTC is now orphaned inside `bridge_id`'s balance.

Contrast this with the `mint` path, which auto-registers the recipient via `mint_inner` before depositing:

```rust
fn mint_inner(&mut self, account_id: &AccountId, amount: U128) {
    if self.token.accounts.get(account_id).is_none() {
        self.token.internal_register_account(account_id);
    }
    self.token.internal_deposit(account_id, amount.into());
``` [2](#0-1) 

`safe_mint` deliberately skips auto-registration but still mints first, creating the accounting split.

The `burn` function withdraws exclusively from `bridge_id`:

```rust
self.token.internal_withdraw(&self.bridge_id, burn_amount.into());
``` [3](#0-2) 

Any orphaned nBTC sitting in `bridge_id` from a failed `safe_mint` call is indistinguishable from legitimately held nBTC and can be consumed by a future `burn` call, meaning a later withdrawal can drain BTC from the bridge without a corresponding user deposit having been credited — a supply-below-backing condition.

The `transfer_nbtc_callback` in the bridge contract does maintain a `lost_found` ledger for failed transfers, but `safe_mint` bypasses that mechanism entirely: [4](#0-3) 

---

### Impact Explanation

**Medium — permanent burning below backed supply / stuck bridge state requiring operator intervention.**

- The nBTC total supply is inflated by `amount` with no corresponding user claim.
- The depositing user's BTC is locked in the bridge with zero nBTC issued and no on-chain recovery path (no `lost_found` entry, no event, no refund trigger).
- The orphaned nBTC in `bridge_id` can be silently consumed by any subsequent `burn` call, causing the bridge to release BTC to a withdrawer without that BTC being backed by a real user deposit — a backed-supply shortfall.

---

### Likelihood Explanation

**Medium.** Any user who sends BTC to a deposit address before their NEAR account is registered on the nBTC contract triggers this path. The deposit address is derived from the user's NEAR account ID and `DepositMsg`, not from their nBTC registration status: [5](#0-4) 

A user can legitimately have a valid NEAR account and a valid deposit address while never having called `storage_deposit` on the nBTC contract. This is a realistic, non-adversarial scenario. An adversary can also deliberately trigger it to inflate the bridge's nBTC balance.

---

### Recommendation

Reverse the order of operations in `safe_mint`: check registration **before** minting. If the account is unregistered, either:

1. Revert (or return early without minting), and let the bridge's callback handle the failure via `lost_found`; or
2. Auto-register the account (matching `mint_inner` behavior) before calling `internal_deposit`.

```rust
// Corrected order
if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));  // no mint has occurred yet
}
self.token.internal_deposit(&self.bridge_id, amount.into());
```

---

### Proof of Concept

1. User derives a deposit address from their NEAR account ID via `DepositMsg` and sends BTC to it.
2. User has never called `storage_deposit` on the nBTC contract — their account is unregistered.
3. A relayer submits the deposit proof; the bridge verifies it and calls `safe_mint(user_account, amount, ...)` on the nBTC contract.
4. `safe_mint` executes `internal_deposit(&self.bridge_id, amount)` — nBTC total supply increases by `amount`, all credited to `bridge_id`.
5. `self.token.accounts.get(&account_id).is_none()` is `true` → function returns `U128(0)`.
6. The bridge contract receives `U128(0)`, interprets the mint as having produced nothing for the user, and creates no `lost_found` entry.
7. The user's BTC is locked in the bridge; the user holds zero nBTC; no recovery path exists.
8. `bridge_id` now holds `amount` extra nBTC. A subsequent `burn(other_user, amount, ...)` call can consume this orphaned balance, releasing BTC from the bridge without a real backing deposit — supply falls below backing.

### Citations

**File:** contracts/nbtc/src/lib.rs (L112-116)
```rust
        self.token.internal_deposit(&self.bridge_id, amount.into());

        if self.token.accounts.get(&account_id).is_none() {
            return PromiseOrValue::Value(U128(0));
        }
```

**File:** contracts/nbtc/src/lib.rs (L158-160)
```rust
        self.token
            .internal_withdraw(&self.bridge_id, burn_amount.into());
        if relayer_fee.0 > 0 {
```

**File:** contracts/nbtc/src/lib.rs (L341-346)
```rust
    fn mint_inner(&mut self, account_id: &AccountId, amount: U128) {
        if self.token.accounts.get(account_id).is_none() {
            self.token.internal_register_account(account_id);
        }
        self.token.internal_deposit(account_id, amount.into());
        near_contract_standards::fungible_token::events::FtMint {
```

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L62-68)
```rust
            self.data_mut()
                .lost_found
                .entry(account_id.clone())
                .and_modify(|v| *v += amount.0)
                .or_insert(amount.0);
            Event::LostFoundNbtc {
                account_id: &account_id,
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L1-10)
```rust
use crate::{
    env, is_structure_equal, near, serde_json, AccountId, Contract, Event, Gas, Value, U128,
};

const MAX_POST_ACTIONS_NUM: usize = 2;
const MAX_TOTAL_POST_ACTIONS_GAS: Gas = Gas::from_tgas(130);
const MAX_PER_POST_ACTIONS_GAS: Gas = Gas::from_tgas(100);
const MIN_PER_POST_ACTIONS_GAS: Gas = Gas::from_tgas(30);

#[near(serializers = [json])]
```
