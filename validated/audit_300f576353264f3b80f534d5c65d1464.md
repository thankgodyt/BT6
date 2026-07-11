### Title
Tokens Minted to Bridge Before Transfer Completes — Silent Loss of User Deposit When Recipient Account Is Unregistered - (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

`safe_mint` in the nBTC token contract unconditionally mints tokens to the bridge's own account before checking whether the recipient has registered storage. If the recipient is unregistered, the function returns `U128(0)` without burning the already-minted tokens, leaving them permanently stranded in the bridge's balance while the user's BTC deposit is locked in the bridge's UTXO set.

---

### Finding Description

In `contracts/nbtc/src/lib.rs`, `safe_mint` follows this sequence:

1. **Mint tokens to `bridge_id`** — `internal_deposit` increases total supply and credits the bridge's own account.
2. **Check if recipient account exists** — if `account_id` has no registered storage, the function returns `PromiseOrValue::Value(U128(0))` immediately.
3. **Transfer to recipient** — only reached if the account exists.

```rust
// contracts/nbtc/src/lib.rs  lines 112-123
self.token.internal_deposit(&self.bridge_id, amount.into());  // (1) always executes

if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));                    // (2) early return, no burn
}

if let Some(msg) = msg {
    self.ft_transfer_call(account_id, amount, None, msg)      // (3) conditional
} else {
    self.ft_transfer(account_id, amount, None);
    PromiseOrValue::Value(amount)
}
```

When step (2) fires, the tokens minted in step (1) are never burned. They remain in the bridge's nBTC balance indefinitely. The bridge's deposit flow has already recorded the UTXO as verified (`verified_deposit_utxo`), so the user's BTC is locked and cannot be refunded via the normal deposit path. The user receives neither nBTC nor their BTC back without manual operator intervention.

This is the direct analog of the external report's pattern: **accounting state is committed before the distribution action completes, and there is no rollback when the action silently fails.**

---

### Impact Explanation

- The user's BTC is permanently locked in the bridge's UTXO set (the deposit is marked verified).
- The nBTC tokens are minted but stranded in the bridge's own account — the user cannot claim them.
- Total nBTC supply increases without a corresponding user-accessible balance, breaking the backed-supply invariant.
- Recovery requires privileged operator intervention (manually transferring the stranded nBTC to the user), which is not guaranteed and is not part of any automated flow.

This matches: **Medium — harmful smart-contract behavior without direct theft, including permanent burning below backed supply, broken callback rollback, or stuck bridge state requiring operator intervention.**

---

### Likelihood Explanation

Any user who sends BTC to a deposit address without first calling `storage_deposit` on the nBTC contract will trigger this path. This is a realistic and common mistake for new users unfamiliar with NEAR's storage registration model. The relayer submitting the proof is a public role and does not check recipient registration before calling the bridge's deposit finalization, which in turn calls `safe_mint`.

---

### Recommendation

`safe_mint` should check whether the recipient account is registered **before** minting. If the account is unregistered, either:
- Revert the entire call so the deposit can be retried after the user registers, or
- Auto-register the account (paying from attached deposit or a protocol reserve) and proceed with the transfer.

The current pattern — mint first, check second, silently return 0 on failure — must be eliminated. The state change (minting) must only be committed after confirming the transfer will succeed.

---

### Proof of Concept

1. Alice sends 0.01 BTC to her bridge deposit address.
2. Alice has never called `storage_deposit` on the nBTC contract, so `token.accounts.get(&alice)` returns `None`.
3. A relayer submits the Merkle proof; the bridge verifies it and calls `safe_mint(alice, 1_000_000, None)`.
4. `internal_deposit(&bridge_id, 1_000_000)` executes — total supply increases by 1,000,000 satoshis, bridge's nBTC balance increases by 1,000,000.
5. `token.accounts.get(&alice).is_none()` is `true` → function returns `U128(0)`.
6. No burn occurs. Bridge's nBTC balance holds 1,000,000 extra tokens.
7. Alice's UTXO is in `verified_deposit_utxo` — she cannot request a refund via the normal refund path.
8. Alice has received 0 nBTC and cannot recover her BTC without operator intervention. [1](#0-0) [2](#0-1)

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
