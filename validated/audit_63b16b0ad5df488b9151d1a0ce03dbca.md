### Title
Unregistered Recipient in `safe_mint` Permanently Traps Minted nBTC in Bridge Balance — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary
`safe_mint` mints `amount` nBTC into the bridge's own token balance unconditionally, then silently returns `U128(0)` if the recipient account is not registered in the token contract — without reversing the mint. The minted tokens are permanently stranded in the bridge's balance while the depositor's BTC remains locked in the bridge's Bitcoin address, causing an irrecoverable loss of user funds.

---

### Finding Description

`safe_mint` in `contracts/nbtc/src/lib.rs` follows this sequence:

1. **Unconditional mint to `bridge_id`**: `self.token.internal_deposit(&self.bridge_id, amount.into())` credits `amount` nBTC to the bridge's own account, increasing total supply.
2. **Unregistered-account early return**: If `self.token.accounts.get(&account_id).is_none()` the function immediately returns `PromiseOrValue::Value(U128(0))` — no transfer, no rollback of the mint.
3. **Tokens stranded**: The `amount` nBTC now sits permanently in `bridge_id`'s balance. No code path later delivers them to the depositor. [1](#0-0) 

The contrast with the regular `mint` path is instructive: `mint` calls `mint_inner`, which always calls `self.token.internal_register_account(account_id)` before depositing, so the account is guaranteed to exist. [2](#0-1) 

`safe_mint` deliberately skips that registration step — but then fails to undo the mint when the account is absent, leaving the accounting in an inconsistent state: total supply is inflated by `amount`, `bridge_id` holds those tokens, and the depositor holds nothing. [3](#0-2) 

---

### Impact Explanation

**Critical — permanent loss of user funds.**

- The depositor's BTC is locked in the bridge's Bitcoin address. The deposit UTXO is marked verified (`verified_deposit_utxo`) and cannot be refunded after a successful deposit proof.
- The minted nBTC is stranded in `bridge_id`'s balance. Because `burn` withdraws from `bridge_id`'s balance by exact amount, subsequent legitimate withdrawals by other users will consume their own correctly-transferred tokens, not the stranded ones — but the stranded tokens inflate `bridge_id`'s balance indefinitely, creating a permanent supply/accounting divergence.
- The depositor receives zero nBTC for their locked BTC with no recovery path. [4](#0-3) 

---

### Likelihood Explanation

**Medium.** NEAR NEP-141 tokens require explicit per-token storage registration. A user who has a NEAR account but has never called `storage_deposit` on the nBTC contract — a routine situation for new bridge users — will trigger this path. The bridge has no on-chain check that the recipient is registered before initiating the deposit flow, so any unregistered depositor reaches `safe_mint` with an unregistered `account_id`. [5](#0-4) 

---

### Recommendation

Either:

1. **Register before minting** (mirror `mint_inner`): call `self.token.internal_register_account(&account_id)` inside `safe_mint` before `internal_deposit`, or
2. **Revert on unregistered account**: move the registration check *before* `internal_deposit` and panic/return an error without minting if the account is absent, or
3. **Reverse the mint on early return**: call `self.token.internal_withdraw(&self.bridge_id, amount.into())` before returning `U128(0)`.

The simplest fix consistent with the existing `mint_inner` pattern:

```rust
pub fn safe_mint(...) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, "...");

    // Guard BEFORE minting
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));
    }

    self.token.internal_deposit(&self.bridge_id, amount.into());
    // ... transfer logic
}
```

---

### Proof of Concept

1. Alice holds a NEAR account (`alice.near`) but has **never** called `storage_deposit` on the nBTC contract — her account is absent from `self.token.accounts`.
2. Alice deposits BTC to her bridge-derived deposit address and submits a Merkle proof.
3. The bridge verifies the proof and calls `safe_mint(alice.near, amount, None)` on the nbtc contract.
4. `self.token.internal_deposit(&self.bridge_id, amount)` executes — `amount` nBTC is minted into `bridge_id`'s balance; total supply increases by `amount`.
5. `self.token.accounts.get(&alice.near)` returns `None`.
6. The function returns `PromiseOrValue::Value(U128(0))` — no transfer occurs, no rollback.
7. Alice's BTC UTXO is now in `verified_deposit_utxo`; she cannot request a refund.
8. Alice holds 0 nBTC. `bridge_id` holds an extra `amount` nBTC that no user can claim. Alice's BTC is permanently locked. [1](#0-0) [6](#0-5)

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

**File:** contracts/nbtc/src/lib.rs (L150-177)
```rust
    pub fn burn(
        &mut self,
        burn_account_id: AccountId,
        burn_amount: U128,
        relayer_account_id: AccountId,
        relayer_fee: U128,
    ) {
        self.assert_bridge();
        self.token
            .internal_withdraw(&self.bridge_id, burn_amount.into());
        if relayer_fee.0 > 0 {
            if self.token.accounts.get(&relayer_account_id).is_none() {
                self.token.internal_register_account(&relayer_account_id);
            }
            self.token.internal_transfer(
                &self.bridge_id,
                &relayer_account_id,
                relayer_fee.into(),
                None,
            );
        }
        near_contract_standards::fungible_token::events::FtBurn {
            owner_id: &burn_account_id,
            amount: burn_amount,
            memo: None,
        }
        .emit();
    }
```

**File:** contracts/nbtc/src/lib.rs (L238-270)
```rust
impl StorageManagement for Contract {
    #[payable]
    fn storage_deposit(
        &mut self,
        account_id: Option<AccountId>,
        registration_only: Option<bool>,
    ) -> StorageBalance {
        self.token.storage_deposit(account_id, registration_only)
    }

    #[payable]
    fn storage_withdraw(&mut self, amount: Option<NearToken>) -> StorageBalance {
        self.token.storage_withdraw(amount)
    }

    #[payable]
    fn storage_unregister(&mut self, force: Option<bool>) -> bool {
        #[allow(unused_variables)]
        if let Some((account_id, balance)) = self.token.internal_storage_unregister(force) {
            log!("Closed @{} with {}", account_id, balance);
            true
        } else {
            false
        }
    }

    fn storage_balance_bounds(&self) -> StorageBalanceBounds {
        self.token.storage_balance_bounds()
    }

    fn storage_balance_of(&self, account_id: AccountId) -> Option<StorageBalance> {
        self.token.storage_balance_of(account_id)
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

**File:** contracts/satoshi-bridge/src/refund.rs (L534-541)
```rust
        // Double-check not finalized (could have been verified between request and callback)
        require!(
            !self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key),
            "UTXO already verified via deposit"
        );
```
