### Title
Unconditional Mint Before Account-Registration Guard Permanently Inflates nBTC Supply — (`contracts/nbtc/src/lib.rs`)

---

### Summary

In `safe_mint`, the nBTC token contract mints tokens to `bridge_id` unconditionally before checking whether the recipient account is registered. When the account is not registered the function returns `U128(0)` without rolling back the already-executed mint, leaving freshly-created nBTC permanently stranded in the bridge account and inflating total supply beyond the BTC-backed amount.

---

### Finding Description

`safe_mint` is the minting entry-point used by the `satoshi-bridge` contract for the "safe deposit" flow (e.g. Omni Bridge). Its body is:

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
    self.token.internal_deposit(&self.bridge_id, amount.into()); // ← mint always fires

    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));                   // ← early return, no rollback
    }

    if let Some(msg) = msg {
        self.ft_transfer_call(account_id, amount, None, msg)
    } else {
        self.ft_transfer(account_id, amount, None);
        PromiseOrValue::Value(amount)
    }
}
``` [1](#0-0) 

The critical ordering flaw:

1. **`internal_deposit(&self.bridge_id, amount)`** — permanently increases `bridge_id`'s token balance and the global total supply. This is a state-mutating operation on the nBTC contract. [2](#0-1) 

2. **Account-registration guard** — only *after* the mint does the function check whether `account_id` is registered. If it is not, the function returns `U128(0)` immediately. No burn, no rollback, no recovery path is executed inside `safe_mint`. [3](#0-2) 

3. **Cross-contract atomicity gap** — the bridge contract calls `safe_mint` as a cross-contract call (XCC). On NEAR, if the bridge's *callback* panics to "revert the deposit on failed XCC calls" (the documented intent of the safe path), only the bridge contract's state is rolled back. The nBTC contract's state — the already-executed `internal_deposit` — is **not** rolled back. The tokens remain in `bridge_id`'s balance with no corresponding BTC backing.

The analog to the reported vulnerability class is exact: a conditional check that should gate the minting operation is placed *after* the mint rather than before it, causing the minting path to execute unconditionally while the delivery path is conditional. When the delivery path is skipped, the system is left in an inconsistent state (tokens minted, not delivered, not rolled back).

---

### Impact Explanation

- **nBTC total supply is permanently inflated** beyond the amount of BTC held by the bridge. The `bridge_id` account accumulates unbacked nBTC tokens.
- **User funds are permanently lost**: the depositor's BTC is locked in the bridge's Bitcoin address, but no nBTC is ever credited to them.
- **Unbacked nBTC in `bridge_id`** can be used by the bridge for subsequent operations (e.g. paying out withdrawals, protocol fees), effectively allowing unbacked nBTC to circulate and breaking the 1:1 peg invariant.

This matches the allowed impact: *"Critical. Significant loss, theft, destruction, or permanent locking of user or protocol funds"* and *"Medium. Permanent burning below backed supply."*

---

### Likelihood Explanation

The `safe_deposit` path is used by Omni Bridge and is expected to pre-register the recipient account. However:

- A user can call `storage_unregister` on the nBTC contract between the time the deposit address is derived and the time the relayer submits the proof, causing the account to be unregistered at mint time.
- Any integration that calls `verify_deposit_v2` with `safe_deposit = Some(..)` without guaranteeing prior storage registration will trigger this path.
- The `safe_verify_deposit` and `safe_verify_deposit_compact` deprecated entrypoints share the same downstream `safe_mint` call. [4](#0-3) 

Likelihood is **medium**: requires the recipient account to be unregistered at mint time, which is an attacker-controllable condition via `storage_unregister`.

---

### Recommendation

Move the account-registration check **before** the `internal_deposit` call, or burn the minted tokens if the transfer cannot proceed:

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
    // Guard BEFORE minting
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));
    }
    self.token.internal_deposit(&self.bridge_id, amount.into());
    // ... transfer logic
}
```

This ensures that if the recipient is not registered, no tokens are ever minted, keeping total supply consistent with the BTC-backed amount.

---

### Proof of Concept

1. Alice sends 0.01 BTC to her bridge deposit address with `safe_deposit = Some(..)`.
2. Alice calls `storage_unregister(force: None)` on the nBTC contract, removing her account registration (possible if her balance is 0 at that moment, or after a prior withdrawal).
3. The relayer submits the deposit proof via `verify_deposit_v2` (or `safe_verify_deposit`).
4. The bridge verifies the proof and calls `safe_mint(alice.near, 1_000_000, None)` on the nBTC contract.
5. `internal_deposit(&bridge_id, 1_000_000)` executes — nBTC total supply increases by 1,000,000 satoshis; `bridge_id`'s balance increases by 1,000,000.
6. `self.token.accounts.get(&alice.near).is_none()` → `true` → function returns `U128(0)`.
7. The bridge's callback receives `U128(0)`, interprets it as failure, and panics to revert its own state. The bridge's deposit record is rolled back.
8. **Result**: Alice's BTC is locked in the bridge's Bitcoin address forever. The nBTC contract has 1,000,000 unbacked satoshis in `bridge_id`'s balance. Total nBTC supply exceeds total BTC held by the bridge. [5](#0-4)

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L81-101)
```rust
        if deposit_msg.safe_deposit.is_some() {
            self.internal_safe_verify_deposit_entry(
                deposit_msg,
                tx_bytes.0,
                vout,
                proof.tx_block_blockhash,
                proof.tx_index,
                proof.merkle_proof,
                coinbase_proof,
            )
        } else {
            self.internal_verify_deposit_entry(
                deposit_msg,
                tx_bytes.0,
                vout,
                proof.tx_block_blockhash,
                proof.tx_index,
                proof.merkle_proof,
                coinbase_proof,
            )
        }
```
