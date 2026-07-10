### Title
Tokens Permanently Stuck in Bridge When Recipient Account Unregistered in `safe_mint` — (File: contracts/nbtc/src/lib.rs)

---

### Summary

The `safe_mint` function in the nBTC token contract mints tokens to the bridge's own balance **before** checking whether the intended recipient account is registered. If the recipient is unregistered, the function silently returns `U128(0)` without reverting, leaving the freshly minted nBTC permanently stranded in the bridge's balance. There is no recovery path (no `lost_found` entry, no retry, no revert), so the corresponding BTC deposit is effectively lost.

---

### Finding Description

In `contracts/nbtc/src/lib.rs` lines 101–124:

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
    self.token.internal_deposit(&self.bridge_id, amount.into()); // ← mints FIRST

    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));                   // ← silent return, tokens stuck
    }
    // transfer to account_id only if registered
    ...
}
```

The sequence is:

1. `internal_deposit(&self.bridge_id, amount)` — increases the bridge's nBTC balance by `amount` and raises `total_supply`.
2. Registration check — if `account_id` has no storage slot, the function returns `U128(0)`.
3. The `amount` tokens now exist in the bridge's balance with **no accounting entry** linking them to the depositor and **no mechanism to reclaim them**.

Contrast this with `mint_inner` (lines 341–352), which is used by the normal `mint` path and **auto-registers** the recipient before crediting them:

```rust
fn mint_inner(&mut self, account_id: &AccountId, amount: U128) {
    if self.token.accounts.get(account_id).is_none() {
        self.token.internal_register_account(account_id); // ← registers first
    }
    self.token.internal_deposit(account_id, amount.into());
    ...
}
```

The `transfer_nbtc_callback` in `contracts/satoshi-bridge/src/token_transfer.rs` (lines 54–75) does populate `lost_found` on failed cross-contract transfers, but `safe_mint` never reaches that callback path — it returns inline, so the bridge's callback layer never learns that the user received nothing.

---

### Impact Explanation

- The user's BTC is locked in the bridge's Bitcoin address (a deposit UTXO is recorded on-chain).
- The corresponding nBTC is minted into the bridge's own fungible-token balance, inflating `total_supply` without any user-accessible balance.
- No `lost_found` entry is created; no event signals the failure; no retry is possible.
- The user permanently loses their deposited BTC with no on-chain recourse.

This constitutes **significant, permanent loss of user funds** — a Critical-severity impact under the allowed scope.

---

### Likelihood Explanation

Any user who initiates a BTC deposit targeting a NEAR account that has not yet called `storage_deposit` on the nBTC contract will trigger this path. NEAR's NEP-141 standard requires explicit storage registration; it is a common user mistake to deposit BTC before registering the destination account. The bridge relayer submits the proof regardless of the recipient's registration status, so the vulnerable `safe_mint` call is reached on every such deposit.

---

### Recommendation

Reorder the check so that the registration gate fires **before** any tokens are minted:

```rust
pub fn safe_mint(...) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, "...");

    // Guard BEFORE minting
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0)); // nothing minted, nothing lost
    }

    self.token.internal_deposit(&self.bridge_id, amount.into());
    // proceed with transfer
    ...
}
```

Alternatively, adopt the same auto-registration pattern used by `mint_inner`, or revert (panic) when the recipient is unregistered so the bridge's callback can handle the failure and record the amount in `lost_found`.

---

### Proof of Concept

1. Alice sends 0.01 BTC to her bridge deposit address.
2. Alice has **not** called `storage_deposit` on the nBTC contract for her NEAR account.
3. A relayer submits the Merkle proof; the bridge verifies it and calls `safe_mint(alice.near, 1_000_000, None)` on the nBTC contract.
4. `internal_deposit(&bridge_id, 1_000_000)` executes — bridge's nBTC balance increases by 1 000 000 satoshis-worth of nBTC; `total_supply` increases by the same amount.
5. `self.token.accounts.get(&alice.near)` returns `None` — Alice is unregistered.
6. `safe_mint` returns `PromiseOrValue::Value(U128(0))`.
7. Alice receives **0 nBTC**. The 1 000 000 units sit in the bridge's balance forever. Alice's 0.01 BTC is permanently locked. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L54-75)
```rust
    pub fn transfer_nbtc_callback(&mut self, account_id: AccountId, amount: U128) -> bool {
        let promise_success = is_promise_success();
        let event = Event::TransferNbtc {
            account_id: &account_id,
            amount,
            success: promise_success,
        };
        if !promise_success {
            self.data_mut()
                .lost_found
                .entry(account_id.clone())
                .and_modify(|v| *v += amount.0)
                .or_insert(amount.0);
            Event::LostFoundNbtc {
                account_id: &account_id,
                amount,
            }
            .emit();
        }
        event.emit();
        promise_success
    }
```
