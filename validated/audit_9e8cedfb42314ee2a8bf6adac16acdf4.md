Looking at the `ft_transfer` implementation in detail:

### Title
Silent Token Lock via `ft_transfer` Fallthrough When Withdraw Relayer Is Unset — (`contracts/nbtc/src/lib.rs`)

---

### Summary

The `ft_transfer` override in the nBTC contract contains a missing `else`/`require!` branch. When `receiver_id == current_account_id()` and the memo starts with `WITHDRAW_TO:`, but no withdraw relayer has been configured, execution silently falls through and transfers the caller's tokens to the nBTC contract's own FT account. No recovery function exists in the contract, so those tokens are locked until operator intervention.

---

### Finding Description

The relevant logic is:

```rust
// contracts/nbtc/src/lib.rs  lines 183–196
fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
    if receiver_id == env::current_account_id()
        && memo.as_ref().is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
    {
        if let Some(withdraw_relayer) = Self::read_withdraw_relayer_address() {
            return self.token.ft_transfer(withdraw_relayer, amount, memo);
        }
        // ← no else / no require! / no panic
    }
    self.token.ft_transfer(receiver_id, amount, memo);   // receiver_id == nbtc_contract
}
``` [1](#0-0) 

When `read_withdraw_relayer_address()` returns `None`, the inner `if let` is skipped and the outer `if` block exits without returning. Control falls to line 195, which calls `self.token.ft_transfer(nbtc_contract, amount, memo)` — transferring the caller's tokens to the contract's own FT balance. [2](#0-1) 

**Prerequisite — registering the nBTC contract's own account:**  
The constructor only registers `bridge_id`: [3](#0-2) 

The nBTC contract's own account is not registered by default. However, `storage_deposit` is fully public and unrestricted: [4](#0-3) 

Any caller can register the nBTC contract's own account with a small NEAR deposit, satisfying the prerequisite. After that, `self.token.ft_transfer(nbtc_contract, ...)` succeeds instead of panicking.

**No recovery path:**  
`burn` withdraws only from `bridge_id`, not from `current_account_id()`: [5](#0-4) 

No other function in the contract can move tokens out of the nBTC contract's own FT balance. Recovery requires a contract upgrade by the operator.

---

### Impact Explanation

Any user (including a legitimate Near Intents user) who calls `ft_transfer(nbtc_contract, amount, "WITHDRAW_TO:<btc_addr>")` while the withdraw relayer is unset will have their nBTC silently deposited into the contract's own account with no on-chain recovery path. This constitutes attacker-triggered (or inadvertent) temporary locking of bridged funds requiring operator intervention — matching the **Medium** impact tier.

---

### Likelihood Explanation

- The withdraw relayer is absent during any window between deployment and the first `set_withdraw_relayer_address` call, or after a relayer rotation where the key is cleared.
- Registering the nBTC contract's own account costs only a small NEAR storage deposit and is a single public call.
- Near Intents users are expected to use exactly this `ft_transfer` + `WITHDRAW_TO:` pattern, so the trigger is part of the documented usage flow.

---

### Recommendation

Add an explicit `require!` (or `panic!`) in the fallthrough case so that a missing relayer causes a clean revert rather than a silent misdirected transfer:

```rust
fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
    if receiver_id == env::current_account_id()
        && memo.as_ref().is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
    {
        let withdraw_relayer = Self::read_withdraw_relayer_address()
            .expect("Withdraw relayer not configured");
        return self.token.ft_transfer(withdraw_relayer, amount, memo);
    }
    self.token.ft_transfer(receiver_id, amount, memo);
}
```

---

### Proof of Concept

1. Deploy the nBTC contract without calling `set_withdraw_relayer_address`.
2. Call `storage_deposit(account_id = nbtc_contract, registration_only = true)` with sufficient NEAR to register the contract's own FT account.
3. Mint some nBTC to `alice`.
4. As `alice`, call `ft_transfer(receiver_id = nbtc_contract, amount = 1000, memo = "WITHDRAW_TO:bc1qxxx")` with 1 yoctoNEAR attached.
5. Assert: `ft_balance_of(alice)` decreased by 1000; `ft_balance_of(nbtc_contract)` increased by 1000; no withdrawal was initiated; no revert occurred.

### Citations

**File:** contracts/nbtc/src/lib.rs (L86-89)
```rust
        contract
            .token
            .internal_register_account(&contract.bridge_id);

```

**File:** contracts/nbtc/src/lib.rs (L158-159)
```rust
        self.token
            .internal_withdraw(&self.bridge_id, burn_amount.into());
```

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

**File:** contracts/nbtc/src/lib.rs (L239-246)
```rust
    #[payable]
    fn storage_deposit(
        &mut self,
        account_id: Option<AccountId>,
        registration_only: Option<bool>,
    ) -> StorageBalance {
        self.token.storage_deposit(account_id, registration_only)
    }
```

**File:** contracts/nbtc/src/lib.rs (L354-356)
```rust
    fn read_withdraw_relayer_address() -> Option<AccountId> {
        env::storage_read(WITHDRAW_RELAYER_ADDRESS).and_then(|data| borsh::from_slice(&data).ok())
    }
```
