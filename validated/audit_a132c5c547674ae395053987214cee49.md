### Title
Silent nBTC Loss in `safe_mint` When Recipient Account Is Unregistered — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

The `safe_mint` function in the nBTC token contract mints tokens to the bridge's own account **before** checking whether the intended recipient is registered. If the recipient has no storage registration, the function silently returns `U128(0)` without reverting the mint. The minted nBTC is permanently stranded in the bridge's account while the user's BTC remains locked in the bridge's UTXO pool with no recovery path.

---

### Finding Description

`safe_mint` (the deposit-path minting entry point callable only by the bridge) executes in this order:

1. **Mint to bridge first** — `self.token.internal_deposit(&self.bridge_id, amount.into())` unconditionally increases the bridge's nBTC balance by `amount`.
2. **Check recipient registration** — only *after* the mint does it test `self.token.accounts.get(&account_id).is_none()`.
3. **Silent early return** — if the recipient is unregistered, the function returns `PromiseOrValue::Value(U128(0))` with no revert, no burn, and no lost-found entry. [1](#0-0) 

The result is that `amount` nBTC tokens are created and credited to the bridge's account, but the user receives nothing. Compare this with `mint_inner`, which is used by the `mint` path and **auto-registers** any unregistered account before depositing: [2](#0-1) 

`safe_mint` deliberately skips that auto-registration, but it does not skip the prior `internal_deposit` to the bridge — that is the root cause.

The bridge's account is pre-registered at construction time, so it can always hold tokens: [3](#0-2) 

There is no on-chain mechanism (no claim function, no lost-found entry, no refund hook) that would let the user later retrieve the nBTC that accumulated in the bridge's account under this path.

---

### Impact Explanation

- The user's BTC deposit is locked in the bridge's UTXO pool. Once the bridge's deposit flow calls `safe_mint` and the UTXO is marked verified, the refund path is blocked (`"UTXO already verified via deposit, cannot refund"`). [4](#0-3) 

- The corresponding nBTC sits in the bridge's account, indistinguishable from protocol-fee tokens or other bridge-held balances, and can be spent by the bridge for unrelated purposes (e.g., protocol-fee withdrawals via `internal_withdraw_protocol_fee`). [5](#0-4) 

- The user has permanently lost their BTC with no on-chain recourse. This matches **Critical — significant loss or permanent locking of user funds**.

---

### Likelihood Explanation

NEP-141 on NEAR requires explicit storage registration before a token account can hold a balance. A user who sends BTC to the bridge deposit address without first calling `storage_deposit` on the nBTC contract — a common omission for new users, wallet integrations, or smart-contract callers — will trigger this path every time the bridge uses `safe_mint`. The trigger requires no special privilege: any BTC deposit to a valid bridge address is sufficient.

---

### Recommendation

Reorder the operations in `safe_mint` so that the registration check (or auto-registration) happens **before** `internal_deposit`:

```rust
pub fn safe_mint(...) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, "...");

    // Guard BEFORE minting
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));
    }

    self.token.internal_deposit(&self.bridge_id, amount.into());
    // ... transfer to account_id
}
```

Alternatively, auto-register the recipient (as `mint_inner` does) so the transfer always succeeds. If a silent-return semantic is intentional, the bridge's deposit callback must detect the `U128(0)` return and either burn the stranded tokens or record them in `lost_found` for the user to claim.

---

### Proof of Concept

1. User derives their bridge deposit address and sends BTC, but has **never** called `storage_deposit` on the nBTC contract.
2. A relayer submits the Merkle inclusion proof; the bridge verifies it and calls `safe_mint(user_account_id, deposit_amount, None)`.
3. Inside `safe_mint`, `self.token.internal_deposit(&self.bridge_id, deposit_amount)` executes — bridge nBTC balance increases by `deposit_amount`.
4. `self.token.accounts.get(&user_account_id).is_none()` → `true`; function returns `U128(0)`.
5. The UTXO is now in `verified_deposit_utxo`; calling `request_refund` for the same UTXO panics with `"UTXO already verified via deposit, cannot refund"`.
6. The user holds 0 nBTC and cannot recover their BTC. The `deposit_amount` nBTC is silently absorbed into the bridge's account with no audit trail linking it to the user. [6](#0-5)

### Citations

**File:** contracts/nbtc/src/lib.rs (L86-90)
```rust
        contract
            .token
            .internal_register_account(&contract.bridge_id);

        contract
```

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

**File:** contracts/satoshi-bridge/src/refund.rs (L254-258)
```rust
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );
```

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L11-21)
```rust
    pub fn internal_withdraw_protocol_fee(&self, amount: u128) -> Promise {
        ext_ft_core::ext(self.internal_config().nbtc_account_id.clone())
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .with_static_gas(GAS_FOR_TOKEN_TRANSFER)
            .ft_transfer(env::predecessor_account_id(), amount.into(), None)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_AFTER_TOKEN_TRANSFER)
                    .withdraw_protocol_fee_callback(amount.into()),
            )
    }
```
