### Title
`safe_mint` Mints Tokens to Bridge Before Checking Recipient Registration, Returns Zero on Unregistered Account — Broken nBTC Supply Accounting - (File: contracts/nbtc/src/lib.rs)

---

### Summary

The `safe_mint` function in `contracts/nbtc/src/lib.rs` unconditionally mints `amount` nBTC tokens into `bridge_id`'s balance before checking whether the intended recipient account is registered. If the recipient is not registered, the function returns `PromiseOrValue::Value(U128(0))` without ever transferring the tokens. The bridge caller receives `U128(0)` — signaling "zero tokens delivered" — while the nBTC total supply has already been permanently inflated by `amount`. This is a direct analog to the "overreporting of losses" class: the function reports a failure (zero minted to the user) when no actual failure occurred (tokens were minted to `bridge_id`), breaking bridge supply accounting.

---

### Finding Description

In `contracts/nbtc/src/lib.rs`, `safe_mint` executes in this order:

**Step 1 — Unconditional mint to bridge (line 112):**
```rust
self.token.internal_deposit(&self.bridge_id, amount.into());
```
`amount` nBTC tokens are minted into `bridge_id`'s balance. The total supply increases by `amount` at this point.

**Step 2 — Recipient registration check (lines 114–116):**
```rust
if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));
}
```
If the recipient is not registered, the function returns immediately with `U128(0)`. No transfer occurs. The `amount` tokens remain in `bridge_id`'s balance with no accounting entry linking them to the deposit.

**Step 3 — Transfer (lines 118–123, only reached if registered):**
```rust
if let Some(msg) = msg {
    self.ft_transfer_call(account_id, amount, None, msg)
} else {
    self.ft_transfer(account_id, amount, None);
    PromiseOrValue::Value(amount)
}
```

The bridge caller (satoshi-bridge contract) receives `U128(0)` from `safe_mint` and has no way to distinguish "recipient not registered, tokens silently minted to bridge_id" from a genuine zero-mint. The nBTC total supply is now higher than the bridge's internal accounting reflects. [1](#0-0) 

---

### Impact Explanation

- **Supply inflation**: Every call to `safe_mint` for an unregistered recipient permanently inflates the nBTC total supply by `amount` without a corresponding tracked deposit. The bridge's internal accounting (UTXOs, pending infos, verified deposits) records no mint, while the token contract's `total_supply` increases.
- **Tokens stranded in bridge_id**: The minted tokens accumulate in `bridge_id`'s nBTC balance. They are not tracked by `lost_found` (which is only populated by `transfer_nbtc_callback` on failed `ft_transfer` calls, not by `safe_mint` returning zero). There is no automatic recovery path.
- **Accounting divergence**: The bridge believes the deposit produced zero tokens; the token contract records `amount` new tokens in circulation. This divergence grows with each such event and cannot be corrected without manual governance intervention — matching the "vault shares underpriced until manual interaction" consequence of the original report.

**Allowed impact match**: Medium — "Harmful smart-contract behavior without direct funds theft, including permanent burning below backed supply, broken callback rollback, or stuck bridge state requiring operator intervention."

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
