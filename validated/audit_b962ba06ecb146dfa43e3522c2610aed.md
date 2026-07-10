### Title
`safe_mint` Mints nBTC to Bridge Before Checking Recipient Registration, Causing Permanent Fund Loss for Unregistered Accounts — (`contracts/nbtc/src/lib.rs`)

---

### Summary

The `safe_mint` function in the nBTC token contract unconditionally mints tokens to the bridge's own account before verifying that the intended recipient (`account_id`) is registered in the token contract. When the recipient is not registered, the function returns `U128(0)` without transferring the newly minted tokens, leaving them permanently stranded in the bridge's balance with no recovery path.

---

### Finding Description

In `contracts/nbtc/src/lib.rs`, the `safe_mint` function executes `internal_deposit` to credit the bridge account with `amount` tokens, then checks whether `account_id` is registered:

```rust
// contracts/nbtc/src/lib.rs lines 112–116
self.token.internal_deposit(&self.bridge_id, amount.into());

if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));
}
```

The state-changing mint (`internal_deposit`) happens unconditionally before the registration guard. If `account_id` has no storage slot in the token contract, the function returns early with zero, and the minted tokens remain in `bridge_id`'s balance forever. There is no rollback, no lost-and-found entry, and no event that would allow the bridge to detect or recover the stranded amount.

The analog to the external report is direct: just as `IERC20Detailed(_asset).decimals()` is called on the zero-address after the amount sentinel is detected — causing a revert — here the registration check is evaluated *after* the mint executes, causing silent, irrecoverable fund loss when the edge-case condition (unregistered account) is true.

---

### Impact Explanation

- The BTC deposit is consumed and the corresponding UTXO is recorded as verified on the NEAR side.
- nBTC equal to the deposit amount is minted into the bridge's own balance, inflating the bridge's holdings without a corresponding user credit.
- The user receives nothing; their BTC is permanently locked.
- The bridge's nBTC balance grows beyond what is owed to real users, breaking the 1:1 backing invariant.

This constitutes **significant, permanent loss of user funds** and a **broken bridge accounting invariant**.

---

### Likelihood Explanation

The `safe_mint` path is exercised by the safe-deposit flow (`safe_verify_deposit` / `verify_deposit_v2` with `safe_deposit = Some(..)`), which is the recommended path for integrations such as Omni Bridge. Any depositor whose NEAR account has not previously called `storage_deposit` on the nBTC contract — a common situation for first-time users or programmatic integrations — will trigger this branch. No attacker action is required; the condition arises from ordinary user behavior.

---

### Recommendation

Move the registration check **before** the mint, and return early without minting if the account is unregistered:

```rust
pub fn safe_mint(...) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, "...");

    // Guard BEFORE any state change
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));
    }

    self.token.internal_deposit(&self.bridge_id, amount.into());
    // ... transfer logic
}
```

Alternatively, register the account automatically (using attached NEAR already required by the safe-deposit caller) before minting, mirroring the pattern used in `burn` for the relayer account.

---

### Proof of Concept

1. User deposits BTC on-chain; a relayer calls `verify_deposit_v2` with `safe_deposit = Some(..)`.
2. The bridge's deposit handler calls `ext_nbtc::safe_mint(user_account_id, amount, msg)`.
3. `user_account_id` has never called `storage_deposit` on the nBTC contract.
4. Inside `safe_mint`:
   - Line 112: `self.token.internal_deposit(&self.bridge_id, amount.into())` — bridge balance increases by `amount`, total supply increases.
   - Line 114: `self.token.accounts.get(&account_id).is_none()` → `true`.
   - Line 115: returns `U128(0)`.
5. The user receives 0 nBTC. The bridge holds `amount` extra nBTC with no owner. The BTC UTXO is marked verified and cannot be re-deposited. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** contracts/satoshi-bridge/src/nbtc/mod.rs (L25-25)
```rust
    fn safe_mint(&mut self, account_id: AccountId, amount: U128, msg: Option<String>);
```
