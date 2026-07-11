### Title
`safe_mint` Mints nBTC to Bridge Without Delivering to Unregistered Recipient — (`contracts/nbtc/src/lib.rs`)

### Summary

The `safe_mint` function in the nBTC token contract unconditionally mints tokens to the bridge's own account before checking whether the intended recipient is registered. If the recipient has no storage registration, the function silently returns `U128(0)` without transferring the newly minted tokens, leaving them permanently stranded in the bridge's account with no recovery path for the depositing user.

### Finding Description

`safe_mint` in `contracts/nbtc/src/lib.rs` follows this sequence:

1. **Mint to bridge first** — `self.token.internal_deposit(&self.bridge_id, amount.into())` unconditionally increases the bridge's nBTC balance by the full deposit amount.
2. **Check recipient registration** — `if self.token.accounts.get(&account_id).is_none()` tests whether the intended recipient has a storage account.
3. **Silent early return** — if the recipient is unregistered, the function returns `PromiseOrValue::Value(U128(0))` immediately, with no transfer and no entry into the `lost_found` ledger. [1](#0-0) 

The contrast with `mint_inner` (used by the privileged `mint` function) is instructive: `mint_inner` auto-registers the recipient before depositing, so it never leaves tokens stranded. [2](#0-1) 

The `lost_found` recovery ledger is populated only inside `transfer_nbtc_callback` when an explicit transfer fails after the fact; `safe_mint`'s early-return path never reaches that code. [3](#0-2) 

### Impact Explanation

When triggered:

- The user's BTC is locked in the on-chain deposit address (the deposit proof has been accepted).
- nBTC equal to the deposit amount is minted into the bridge's own account, inflating the bridge's balance without a corresponding user credit.
- The user receives zero nBTC and has no on-chain mechanism to claim the stranded tokens.
- The bridge's nBTC balance exceeds what it legitimately holds, breaking the 1:1 BTC-to-nBTC backing invariant.
- Recovery requires privileged operator intervention (manual transfer from the bridge's nBTC balance), which is not guaranteed and is not documented as a recovery path.

This matches the allowed Medium impact: *"permanent burning below backed supply"* and *"stuck bridge state requiring operator intervention."*

### Likelihood Explanation

NEAR NEP-141 storage registration is a prerequisite that many users overlook. A user who generates a deposit address and sends BTC before calling `storage_deposit` on the nBTC contract will land in this state. The bridge has no pre-flight check that the recipient is registered before calling `safe_mint`, and the silent `U128(0)` return gives the caller no actionable signal to retry or refund.

### Recommendation

Mirror the pattern used by `mint_inner`: auto-register the recipient before depositing, eliminating the unregistered-account branch entirely.

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
+   if self.token.accounts.get(&account_id).is_none() {
+       self.token.internal_register_account(&account_id);
+   }
    self.token.internal_deposit(&self.bridge_id, amount.into());
-   if self.token.accounts.get(&account_id).is_none() {
-       return PromiseOrValue::Value(U128(0));
-   }
    ...
}
```

Alternatively, if the intent is to reject unregistered recipients, the registration check must be performed **before** `internal_deposit`, and any rejection must revert the mint (or never perform it).

### Proof of Concept

1. Alice generates a deposit address tied to her NEAR account `alice.near`.
2. Alice sends 0.01 BTC to the deposit address but has not called `storage_deposit` on the nBTC contract for `alice.near`.
3. A relayer submits the BTC transaction proof; the bridge accepts it and calls `safe_mint("alice.near", 1_000_000, None)` on the nBTC contract.
4. `internal_deposit(&self.bridge_id, 1_000_000)` executes — the bridge's nBTC balance increases by 1,000,000 satoshis.
5. `self.token.accounts.get(&"alice.near")` returns `None` — the function returns `U128(0)`.
6. Alice's nBTC balance remains zero. The bridge holds 1,000,000 nBTC that are not backed by any new BTC (the BTC was already credited to the deposit address). Alice's BTC is effectively lost with no on-chain recovery path. [4](#0-3)

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

**File:** contracts/nbtc/src/lib.rs (L341-352)
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
    }
```

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L61-67)
```rust
        if !promise_success {
            self.data_mut()
                .lost_found
                .entry(account_id.clone())
                .and_modify(|v| *v += amount.0)
                .or_insert(amount.0);
            Event::LostFoundNbtc {
```
