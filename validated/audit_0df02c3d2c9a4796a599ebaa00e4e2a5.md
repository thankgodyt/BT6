### Title
`ft_transfer` silently locks nBTC tokens in the token contract itself when `withdraw_relayer` is not configured — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

The overridden `ft_transfer` in the nBTC contract contains a legacy bridging path (Near Intents) that is supposed to redirect tokens to a configured `withdraw_relayer` when the memo starts with `WITHDRAW_TO:`. If `withdraw_relayer` has never been set, the conditional silently falls through and sends the tokens to the nBTC contract's own account, where they are permanently locked with no recovery path.

---

### Finding Description

`ft_transfer` is overridden in `contracts/nbtc/src/lib.rs` to intercept transfers directed at the nBTC contract itself when the memo carries the `WITHDRAW_MEMO_PREFIX`: [1](#0-0) 

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
        // ← NO revert here; falls through silently
    }

    self.token.ft_transfer(receiver_id, amount, memo);   // sends to nBTC contract itself
}
```

When `read_withdraw_relayer_address()` returns `None` (i.e., the relayer was never configured via `set_withdraw_relayer_address`), the inner `if let Some(...)` branch is skipped entirely. Execution falls through to the final `self.token.ft_transfer(receiver_id, amount, memo)` call, where `receiver_id` is still `env::current_account_id()` — the nBTC contract itself. [2](#0-1) 

The `set_withdraw_relayer_address` function only writes to storage; there is no corresponding unset/delete, and no default value is stored at initialization. On any deployment where the controller has not yet called `set_withdraw_relayer_address`, the storage key is absent and `read_withdraw_relayer_address` returns `None`.

<cite repo="Lauraivanka/btc-bridge--014" path="contracts/nbtc/src/lib.rs" start="324" end="

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

**File:** contracts/nbtc/src/lib.rs (L354-356)
```rust
    fn read_withdraw_relayer_address() -> Option<AccountId> {
        env::storage_read(WITHDRAW_RELAYER_ADDRESS).and_then(|data| borsh::from_slice(&data).ok())
    }
```
