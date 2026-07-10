### Title
Silent Token Loss in `safe_mint` When Recipient Account Is Unregistered — (File: `contracts/nbtc/src/lib.rs`)

### Summary
The `safe_mint` function in the nBTC token contract unconditionally mints tokens to the bridge's own balance before checking whether the recipient account is registered. If the recipient is not registered, the function silently returns `U128(0)` without transferring the tokens, leaving them permanently stranded in the bridge's nBTC balance while the user's BTC deposit is consumed and marked verified.

### Finding Description
In `contracts/nbtc/src/lib.rs`, `safe_mint` executes in this order:

1. `self.token.internal_deposit(&self.bridge_id, amount.into())` — tokens are minted into the bridge's own nBTC balance unconditionally.
2. `if self.token.accounts.get(&account_id).is_none() { return PromiseOrValue::Value(U128(0)); }` — if the recipient has no registered storage account, the function returns early with zero, **without reversing the mint**. [1](#0-0) 

The tokens are now credited to the bridge's nBTC balance. The bridge's deposit callback receives `U128(0)` as the reported transferred amount. Because the deposit UTXO is marked verified in the bridge's state (preventing any future `verify_deposit` or `request_refund` from succeeding on the same UTXO), the user's BTC is permanently locked with no nBTC ever reaching them.

This is precisely the class of bug the external report describes: the bridge's unit tests mock the nBTC contract and assume `safe_mint` always delivers tokens; the nBTC unit tests exercise `safe_mint` in isolation. Neither catches the cross-component failure where an unregistered recipient causes a silent partial-mint that the bridge's callback does not roll back.

### Impact Explanation
- The user's BTC deposit is accepted and the UTXO is marked verified — no refund path remains.
- `internal_deposit` increases the nBTC total supply, but the tokens sit in the bridge's own balance rather than the user's.
- The bridge's nBTC balance is inflated by the stranded amount, silently breaking the 1:1 BTC-backing invariant from the user's perspective.
- Impact: **Critical** — permanent locking/loss of user funds. [2](#0-1) 

### Likelihood Explanation
In NEAR, NEP-141 token receipt requires an explicit `storage_deposit` call on the token contract. Any user who deposits BTC without first registering their account on the nBTC contract triggers this path. New users, users interacting via third-party frontends, or users whose storage registration expired are all realistic victims. The entry point (`safe_verify_deposit` → bridge callback → `safe_mint`) is fully public and requires no privileged access.

### Recommendation
Reverse the order of operations: check registration **before** minting. If the account is unregistered, either panic (forcing the bridge callback to treat the deposit as failed and initiate a refund), or auto-register the account and proceed. Do not mint tokens to the bridge's balance before confirming the transfer can complete.

```rust
pub fn safe_mint(...) -> PromiseOrValue<U128> {
    self.assert_bridge();
    // Check registration BEFORE minting
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0)); // bridge callback must handle refund
    }
    self.token.internal_deposit(&self.bridge_id, amount.into());
    // ... proceed with transfer
}
```

The bridge's callback for `safe_mint` must also explicitly treat a `U128(0)` return as a failure and trigger the refund/lost-found path rather than silently accepting it as success.

### Proof of Concept
1. Alice sends 0.01 BTC to her bridge deposit address.
2. Alice has **not** called `storage_deposit` on the nBTC contract (her account is unregistered).
3. A relayer calls `safe_verify_deposit` on the bridge with a valid Merkle proof.
4. The bridge verifies the proof via the Light Client and calls `nbtc.safe_mint(alice, 1_000_000, None)`.
5. Inside `safe_mint`: `internal_deposit(&bridge_id, 1_000_000)` executes — 1,000,000 satoshi-units of nBTC are minted to the bridge's own balance.
6. `self.token.accounts.get(&alice)` returns `None` → function returns `U128(0)`.
7. The bridge's deposit callback receives `0` as the transferred amount but the UTXO is already marked verified.
8. Alice's BTC is permanently locked; she holds zero nBTC; the bridge's nBTC balance is inflated by 1,000,000 units with no corresponding user backing. [1](#0-0) [3](#0-2)

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
