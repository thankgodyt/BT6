### Title
Tokens Minted to Bridge Before Recipient Registration Check in `safe_mint` Causes Permanent User Fund Loss - (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

In `contracts/nbtc/src/lib.rs`, the `safe_mint` function mints nBTC tokens to the bridge's own account **before** checking whether the intended recipient (`account_id`) has a registered storage account. If the recipient is not registered, the function returns early with `U128(0)`, leaving the minted tokens permanently stranded in the bridge's balance with no recovery path for the user.

---

### Finding Description

The `safe_mint` function in the nBTC token contract follows this sequence:

1. Calls `self.token.internal_deposit(&self.bridge_id, amount.into())` — this immediately increases the bridge's nBTC balance and the total supply.
2. Checks `if self.token.accounts.get(&account_id).is_none()` — if the recipient has no registered storage account, returns `PromiseOrValue::Value(U128(0))`.
3. Only if the account exists does it proceed to `ft_transfer` or `ft_transfer_call` to deliver tokens to the user. [1](#0-0) 

The critical ordering flaw is that `internal_deposit` (the state-mutating mint) executes unconditionally before the account-existence guard. When the guard fires and the function returns early, the minted tokens remain in `bridge_id`'s balance. There is no rollback, no burn, and no entry in the `lost_found` ledger for this case. [2](#0-1) 

This is structurally identical to the external report's bug: in that report, `_incrementGeneration()` (a state mutation) was placed before the mint-count update, so the price calculation read stale state and the user was charged incorrectly. Here, `internal_deposit` (a state mutation) is placed before the account-existence check, so when the check fails the state mutation is not undone.

The `lost_found` recovery mechanism in the bridge handles failed `ft_transfer` cross-contract calls, but it is never populated in this early-return path — the failure is silent and local to the nBTC contract. [3](#0-2) 

---

### Impact Explanation

- The user's BTC is locked on the Bitcoin side (the deposit is verified and accepted by the bridge).
- The corresponding nBTC is minted to the bridge's own account and is not tracked as protocol fee, relayer fee, or `lost_found` — it is simply stranded.
- The user receives no nBTC and has no on-chain mechanism to claim or recover it.
- The bridge's nBTC balance silently inflates beyond what is owed to users, creating an accounting discrepancy between locked BTC and circulating nBTC held by users.
- Recovery requires privileged operator intervention with no automated path.

This matches the **Medium** allowed impact: *broken callback rollback / stuck bridge state requiring operator intervention*, and potentially **Critical**: *significant loss or permanent locking of user funds*.

---

### Likelihood Explanation

The `safe_deposit` field in `DepositMsg` indicates a dedicated "safe deposit" flow exists that routes through `safe_mint`. [4](#0-3) 

Any user who sends BTC using the safe-deposit path but whose NEAR account is not pre-registered in the nBTC token contract (e.g., a new user, or one who never called `storage_deposit` on the nBTC contract) will trigger this path. This is a realistic scenario for new bridge users and requires no special privileges — only a standard BTC deposit with a valid proof.

---

### Recommendation

Move the account-existence check **before** the `internal_deposit` call, so no tokens are minted if the recipient is not registered:

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

+   // Check registration BEFORE minting to avoid stranded tokens
+   if self.token.accounts.get(&account_id).is_none() {
+       return PromiseOrValue::Value(U128(0));
+   }

    self.token.internal_deposit(&self.bridge_id, amount.into());

-   if self.token.accounts.get(&account_id).is_none() {
-       return PromiseOrValue::Value(U128(0));
-   }

    if let Some(msg) = msg {
        self.ft_transfer_call(account_id, amount, None, msg)
    } else {
        self.ft_transfer(account_id, amount, None);
        PromiseOrValue::Value(amount)
    }
}
```

---

### Proof of Concept

1. User Alice sends BTC to her bridge deposit address. Her NEAR account `alice.near` has never called `storage_deposit` on the nBTC contract and is therefore unregistered.
2. A relayer submits the inclusion proof to the bridge via `verify_deposit`.
3. The bridge verifies the proof and calls `safe_mint(alice.near, amount, msg)` on the nBTC contract.
4. `safe_mint` executes `self.token.internal_deposit(&self.bridge_id, amount)` — `amount` nBTC is minted into the bridge's own balance; total supply increases.
5. `self.token.accounts.get(&alice.near)` returns `None` — the function returns `U128(0)`.
6. Alice's BTC is locked. Alice holds zero nBTC. The bridge holds `amount` extra nBTC with no `lost_found` entry and no automated recovery. Alice's funds are permanently inaccessible without operator intervention. [1](#0-0)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L477-484)
```rust
        require!(
            utxo_storage_keys.len() == 1,
            "refund transaction must spend exactly one input"
        );
        // Refund confirmed on-chain → drop the request so no further execute_refund
        // is possible. If it was already removed, this is harmlessly a no-op.
        self.data_mut()
            .refund_requests
```
