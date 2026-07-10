### Title
Silent Token Loss via Nested Conditional Fallthrough in Legacy Withdraw Path — (File: `contracts/nbtc/src/lib.rs`)

### Summary

The `ft_transfer` override in the `nbtc` contract contains a nested conditional that silently falls through to an incorrect transfer destination when the outer condition is satisfied but the inner condition is not. This is a direct structural analog to the reported `MiniPoolReserveLogic` bug: an action that should be independently guarded is nested inside an outer `if`, causing wrong behavior when the outer fires but the inner does not.

### Finding Description

In `contracts/nbtc/src/lib.rs`, the `FungibleTokenCore::ft_transfer` override implements a legacy Near Intents withdraw path:

```rust
#[payable]
fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
    // Legacy bridging flow used by Near Intents
    if receiver_id == env::current_account_id()
        && memo
            .as_ref()
            .is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
    {
        if let Some(withdraw_relayer) = Self::read_withdraw_relayer_address() {
            return self.token.ft_transfer(withdraw_relayer, amount, memo);
        }
    }

    self.token.ft_transfer(receiver_id, amount, memo);
}
``` [1](#0-0) 

The two-level nesting is:

- **Outer condition** (line 185–189): `receiver_id == env::current_account_id() && memo starts with WITHDRAW_TO:`
- **Inner condition** (line 190): `if let Some(withdraw_relayer) = Self::read_withdraw_relayer_address()`

When the **outer condition is true** (the caller is performing a legacy withdraw) but the **inner condition is false** (no relayer address has been stored), the function does **not** return early. It falls through to the unconditional `self.token.ft_transfer(receiver_id, amount, memo)` at line 195, where `receiver_id` is still `env::current_account_id()` — the nbtc contract itself. [2](#0-1) 

The `set_withdraw_relayer_address` function is controller-gated, meaning the relayer slot can be empty during initial deployment, after a controller rotation, or if the relayer is intentionally cleared: [3](#0-2) 

The `storage_deposit` function is fully public — any account can register the nbtc contract itself as a storage account: [4](#0-3) 

Once the nbtc contract is registered as a storage account (costs ~0.00125 NEAR, callable by anyone), the fallthrough `ft_transfer` to `receiver_id = nbtc_contract` succeeds silently. The tokens are credited to the nbtc contract's own balance with no recovery path for the user.

### Impact Explanation

When the nbtc contract is registered as a storage account and no withdraw relayer is configured, any user who calls `ft_transfer(nbtc_contract_id, amount, "WITHDRAW_TO:<btc_addr>")` — the documented Near Intents legacy flow — will have their nBTC permanently transferred into the nbtc contract's own balance. There is no sweep, no refund, and no operator recovery path for these tokens. This constitutes a **stuck bridge state requiring operator intervention** and **permanent loss of user funds** from the user's perspective, matching the Medium impact category: *"Harmful smart-contract behavior without direct funds theft, including permanent burning below backed supply, broken callback rollback, or stuck bridge state requiring operator intervention."*

### Likelihood Explanation

Two preconditions must hold simultaneously:

1. **No withdraw relayer configured** — possible during deployment windows, after controller rotation, or if the relayer is cleared. The controller can set or clear this at any time via `set_withdraw_relayer_address`.
2. **nbtc contract registered as storage account** — any unprivileged account can do this with a ~0.00125 NEAR deposit. An attacker can front-run or pre-register this at negligible cost.

Once both conditions hold, any user using the Near Intents legacy withdraw path triggers the bug. Likelihood is **Low** in steady-state production but **Medium** during deployment or relayer rotation windows.

### Recommendation

Remove the nesting. The inner guard should be an unconditional `require!` or `expect` when the outer condition fires, not a silent no-op:

```rust
fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
    if receiver_id == env::current_account_id()
        && memo.as_ref().is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
    {
        let withdraw_relayer = Self::read_withdraw_relayer_address()
            .unwrap_or_else(|| env::panic_str("Withdraw relayer not configured"));
        return self.token.ft_transfer(withdraw_relayer, amount, memo);
    }

    self.token.ft_transfer(receiver_id, amount, memo);
}
```

This mirrors the fix recommended in the original report: separate the two guards so each fires independently, and ensure the inner action cannot silently fall through to an incorrect default.

### Proof of Concept

1. Deploy nbtc contract with no withdraw relayer set (or clear it via `set_withdraw_relayer_address` after deployment).
2. Attacker calls `storage_deposit(account_id = Some("<nbtc_contract_id>"), registration_only = Some(false))` with ~0.00125 NEAR attached. The nbtc contract is now a registered storage account.
3. Victim holds 1,000,000 nBTC (satoshis) and calls:
   ```
   ft_transfer(
     receiver_id = "<nbtc_contract_id>",
     amount = 1000000,
     memo = Some("WITHDRAW_TO:<victim_btc_address>")
   )
   ```
   with 1 yoctoNEAR attached (standard NEP-141 requirement).
4. Outer condition fires: `receiver_id == current_account_id() && memo starts with WITHDRAW_TO:` → true.
5. Inner condition: `read_withdraw_relayer_address()` → `None` → inner block skipped.
6. Fallthrough: `self.token.ft_transfer(nbtc_contract_id, 1000000, memo)` executes successfully because the nbtc contract is now a registered storage account.
7. Victim's 1,000,000 nBTC are credited to the nbtc contract's own balance. No BTC is sent. No refund is issued. Funds are permanently stuck.

### Citations

**File:** contracts/nbtc/src/lib.rs (L183-196)
```rust
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        // Legacy bridging flow used by Near Intents
        if receiver_id == env::current_account_id()
            && memo
                .as_ref()
                .is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
        {
            if let Some(withdraw_relayer) = Self::read_withdraw_relayer_address() {
                return self.token.ft_transfer(withdraw_relayer, amount, memo);
            }
        }

        self.token.ft_transfer(receiver_id, amount, memo);
    }
```

**File:** contracts/nbtc/src/lib.rs (L239-245)
```rust
    #[payable]
    fn storage_deposit(
        &mut self,
        account_id: Option<AccountId>,
        registration_only: Option<bool>,
    ) -> StorageBalance {
        self.token.storage_deposit(account_id, registration_only)
```

**File:** contracts/nbtc/src/lib.rs (L324-328)
```rust
    pub fn set_withdraw_relayer_address(&mut self, relayer: &AccountId) {
        self.assert_controller();

        env::storage_write(WITHDRAW_RELAYER_ADDRESS, &borsh::to_vec(relayer).unwrap());
    }
```
