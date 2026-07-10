### Title
Silent Token Loss in `safe_mint()` for Unregistered Recipient Accounts — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

The `safe_mint()` function in the nBTC contract mints tokens into the bridge's own balance **before** checking whether the recipient account is registered. If the recipient is unregistered, the function silently returns `U128(0)` and exits, leaving the freshly minted nBTC permanently stranded in the bridge account with no on-chain recovery path for the user.

---

### Finding Description

In `contracts/nbtc/src/lib.rs`, `safe_mint()` executes in this order:

1. `self.token.internal_deposit(&self.bridge_id, amount.into())` — mints `amount` nBTC into the bridge's own NEP-141 balance.
2. `if self.token.accounts.get(&account_id).is_none() { return PromiseOrValue::Value(U128(0)); }` — checks registration **after** minting.
3. If registered, transfers via `ft_transfer` or `ft_transfer_call`. [1](#0-0) 

When the recipient account has no NEP-141 storage deposit (i.e., is not registered), step 2 fires and the function returns early. The tokens minted in step 1 remain in `bridge_id`'s balance. There is no `lost_found` entry created for this case, no event emitted, and no mechanism in the bridge contract to attribute or return those tokens to the depositing user. [2](#0-1) 

This is structurally identical to the reported `deposit_for()` bug: a guard condition fails to account for a valid special state that has already caused a side-effect. There, `require(_locked.end > block.timestamp)` reverts after the call was already dispatched for a perpetual lock (`end == 0`). Here, the registration guard fires **after** `internal_deposit` has already mutated state, causing a silent loss instead of a revert.

The `lost_found` map in the bridge contract handles only failed `ft_transfer` callbacks — it does not cover this case. [3](#0-2) 

---

### Impact Explanation

A user who deposits BTC/ZEC via the bridge using the `safe_deposit` path (which triggers `safe_mint`) but whose NEAR account is not registered for nBTC will have their deposit fully processed on-chain — BTC locked in the bridge UTXO pool, nBTC minted to `bridge_id` — yet receive **zero nBTC**. The minted tokens accumulate silently in the bridge account. No recovery mechanism exists in the production code; remediation requires operator intervention to identify affected deposits and manually redistribute stranded tokens.

**Impact: Medium** — Stuck bridge state / broken deposit delivery requiring operator intervention; user's BTC is locked and nBTC is undelivered.

---

### Likelihood Explanation

Any user who initiates a `safe_deposit` without first calling `storage_deposit` on the nBTC contract triggers this path. This is a realistic scenario for new users unfamiliar with NEP-141 storage registration, or for programmatic depositors that omit the registration step. The `safe_deposit` flag exists precisely to handle edge cases gracefully, making it more likely to be used by users who expect the bridge to handle registration issues — the opposite of what actually happens.

**Likelihood: Medium-High**

---

### Recommendation

Move the registration check **before** `internal_deposit`, or auto-register the account (as `mint_inner` does), so that no tokens are minted if they cannot be delivered:

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

+   // Check registration BEFORE minting to avoid stranding tokens in bridge_id
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));
    }

    self.token.internal_deposit(&self.bridge_id, amount.into());

    if let Some(msg) = msg {
        self.ft_transfer_call(account_id, amount, None, msg)
    } else {
        self.ft_transfer(account_id, amount, None);
        PromiseOrValue::Value(amount)
    }
}
```

---

### Proof of Concept

1. User initiates a BTC deposit with `safe_deposit: true`, targeting a NEAR account that has never called `storage_deposit` on the nBTC contract.
2. The bridge verifies the deposit and calls `safe_mint(account_id, amount, msg)` on the nBTC contract.
3. `internal_deposit(&self.bridge_id, amount)` executes — `amount` nBTC is minted into the bridge's own balance. [4](#0-3) 
4. `self.token.accounts.get(&account_id).is_none()` returns `true` (account not registered). [5](#0-4) 
5. Function returns `PromiseOrValue::Value(U128(0))` — no transfer occurs, no event, no `lost_found` entry.
6. **Result:** User's BTC is locked in the bridge UTXO pool; user holds 0 nBTC; `amount` nBTC sits in `bridge_id` with no user-accessible recovery path.

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

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L54-75)
```rust
    pub fn transfer_nbtc_callback(&mut self, account_id: AccountId, amount: U128) -> bool {
        let promise_success = is_promise_success();
        let event = Event::TransferNbtc {
            account_id: &account_id,
            amount,
            success: promise_success,
        };
        if !promise_success {
            self.data_mut()
                .lost_found
                .entry(account_id.clone())
                .and_modify(|v| *v += amount.0)
                .or_insert(amount.0);
            Event::LostFoundNbtc {
                account_id: &account_id,
                amount,
            }
            .emit();
        }
        event.emit();
        promise_success
    }
```
