### Title
Silent nBTC Inflation via Unguarded Mint Before Registration Check in `safe_mint` — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

`safe_mint` in the nBTC token contract mints tokens to the bridge account **before** checking whether the recipient has a registered storage account. When the recipient is unregistered, the function silently returns `U128(0)` — leaving the freshly minted nBTC permanently stranded in the bridge account while the caller receives no tokens and no revert occurs.

---

### Finding Description

The `safe_mint` function executes in this order:

```rust
// contracts/nbtc/src/lib.rs  lines 101-124
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
    self.token.internal_deposit(&self.bridge_id, amount.into()); // ← tokens minted here

    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));                   // ← silent return, tokens stuck
    }
    // transfer to account_id never reached
    ...
}
``` [1](#0-0) 

Step 1 (`internal_deposit` to `bridge_id`) unconditionally increases the nBTC total supply and credits the bridge account. Step 2 then checks whether `account_id` has a registered storage slot. If it does not, the function returns `U128(0)` — signalling "zero tokens transferred" — without ever moving the newly minted tokens to the user and without burning them back.

By contrast, the standard `mint` path uses `mint_inner`, which **auto-registers** the account before depositing, so the same scenario never arises there:

```rust
// contracts/nbtc/src/lib.rs  lines 341-351
fn mint_inner(&mut self, account_id: &AccountId, amount: U128) {
    if self.token.accounts.get(account_id).is_none() {
        self.token.internal_register_account(account_id);   // ← registers first
    }
    self.token.internal_deposit(account_id, amount.into()); // ← then mints
    ...
}
``` [2](#0-1) 

`safe_mint` is the entry point used by the bridge's **safe-deposit** flow (the path that is supposed to revert cleanly on failure). The bridge calls it as a cross-contract call and inspects the returned `U128` in its callback. When the callback receives `U128(0)` it interprets the mint as having failed and may attempt to revert the deposit — but the nBTC tokens are already minted to `bridge_id` and no burn is issued, so the supply is permanently inflated relative to the BTC actually locked. [3](#0-2) 

---

### Impact Explanation

- **nBTC total supply increases** by `amount` with no corresponding BTC locked for the user.
- The minted tokens sit in the bridge account with no code path to burn them in the failure branch.
- The user's BTC deposit is locked in the bridge's deposit address but they receive zero nBTC.
- The bridge's safe-deposit callback, seeing `U128(0)`, may not mark the UTXO as verified, potentially allowing the same deposit proof to be re-submitted — compounding the supply inflation on each retry.
- Recovery requires privileged operator intervention to manually burn the stranded tokens.

This matches the allowed Medium impact: **broken callback rollback / stuck bridge state requiring operator intervention**, and **permanent supply inflation above backed BTC**.

---

### Likelihood Explanation

Any user whose NEAR account has never called `storage_deposit` on the nBTC contract (i.e., has no registered storage slot) will trigger this path when their BTC deposit is processed via the safe-deposit flow. New users bridging for the first time are the common case. No special attacker capability is required — a normal unprivileged depositor is sufficient.

---

### Recommendation

Move the registration check (or auto-registration) **before** `internal_deposit`, mirroring the pattern used in `mint_inner`:

```rust
pub fn safe_mint(...) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, "...");

    // Guard BEFORE minting
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));
    }

    self.token.internal_deposit(&self.bridge_id, amount.into());
    // ... transfer to account_id
}
```

Alternatively, auto-register the account (as `mint_inner` does) so the early return is never reached.

---

### Proof of Concept

1. Alice deposits BTC via the safe-deposit flow. Her NEAR account has never registered storage on the nBTC contract.
2. The bridge calls `safe_mint(alice.near, 100_000, None)`.
3. `internal_deposit(&bridge_id, 100_000)` executes — nBTC total supply increases by 100 000, bridge account balance = 100 000.
4. `self.token.accounts.get(&alice.near).is_none()` → `true`.
5. Function returns `PromiseOrValue::Value(U128(0))`.
6. Bridge callback receives `0`, treats the mint as failed, does **not** mark the UTXO as verified, does **not** burn the 100 000 nBTC now sitting in the bridge account.
7. Result: 100 000 nBTC are permanently minted with no BTC backing for Alice; Alice's BTC is locked; the bridge's nBTC supply exceeds its BTC collateral. [4](#0-3)

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

**File:** contracts/nbtc/src/lib.rs (L341-351)
```rust
    fn mint_inner(&mut self, account_id: &AccountId, amount: U128) {
        if self.token.accounts.get(account_id).is_none() {
            self.token.internal_register_account(account_id);
        }
        self.token.internal_deposit(account_id, amount.into());
        near_contract_standards::fungible_token::events::FtMint {
            owner_id: account_id,
            amount,
            memo: None,
        }
        .emit();
```
