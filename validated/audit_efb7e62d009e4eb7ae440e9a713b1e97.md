### Title
Tokens Minted to Bridge Account Without User Delivery in `safe_mint()` Causes Irrecoverable State Inconsistency — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

In `safe_mint()`, the nBTC contract mints tokens to the bridge's own account **before** checking whether the intended recipient is registered. If the recipient is unregistered, the function silently returns `U128(0)` and the minted tokens remain in the bridge's account with no recovery path for the user. This is a direct analog to the reported vulnerability class: a partial state write that omits a critical field (the user's balance update), leaving the contract in a misaligned accounting state.

---

### Finding Description

In `contracts/nbtc/src/lib.rs`, `safe_mint()` executes in this order:

1. **Line 112** — unconditionally mints `amount` tokens into the bridge's own account, increasing total supply and the bridge's balance:
   ```rust
   self.token.internal_deposit(&self.bridge_id, amount.into());
   ```
2. **Lines 114–116** — checks whether the recipient account is registered. If it is **not**, the function returns immediately with `U128(0)`:
   ```rust
   if self.token.accounts.get(&account_id).is_none() {
       return PromiseOrValue::Value(U128(0));
   }
   ```
3. **Lines 118–123** — only if the account exists does it transfer the tokens to the user.

The contrast with `mint_inner()` (lines 341–351) is instructive: `mint_inner` auto-registers the account before depositing, so no tokens are ever stranded. `safe_mint` performs the deposit first and the registration check second, inverting the safe order.

When the early-return path is taken:
- `ft_total_supply()` has increased by `amount`.
- The bridge's nBTC balance has increased by `amount`.
- The user's nBTC balance is **unchanged**.
- No `lost_found` entry is created for the user.
- No event is emitted to signal the failure.
- There is no subsequent call path that re-attempts delivery or refunds the minted tokens. [1](#0-0) [2](#0-1) 

---

### Impact Explanation

**Medium — Stuck bridge state / broken callback rollback / supply backed below user-held amount.**

Every invocation of `safe_mint` where the recipient is unregistered permanently inflates the bridge's nBTC balance relative to what users actually hold. The bridge's own nBTC balance is the pool from which `burn()` withdraws when finalizing withdrawals:

```rust
self.token.internal_withdraw(&self.bridge_id, burn_amount.into());
``` [3](#0-2) 

Stranded tokens silently pad that pool, masking the accounting mismatch. The affected user receives no nBTC and has no on-chain mechanism to claim the minted amount later (no `lost_found` entry, no retry path). If the corresponding BTC deposit UTXO was already added to the bridge's available set, the user's BTC is effectively locked: the deposit is considered processed, but the user holds nothing.

---

### Likelihood Explanation

`safe_mint` is a public bridge-callable entry point distinct from the standard `mint`. It is reachable whenever the bridge contract invokes it for a NEAR account that has not called `storage_deposit` on the nBTC contract. A user can legitimately deposit BTC to a derived address before ever interacting with the nBTC contract (no registration required on the Bitcoin side). The relayer then submits the proof and the bridge calls `safe_mint`. If the NEAR recipient has not pre-registered, the early-return path fires. No privileged access or key compromise is required; the trigger is ordinary user behavior (depositing BTC before registering the nBTC account).

---

### Recommendation

Reorder the operations so that the registration check precedes the mint, mirroring `mint_inner`:

```rust
pub fn safe_mint(...) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, "...");

    // Check registration BEFORE minting
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));
    }

    self.token.internal_deposit(&self.bridge_id, amount.into());
    // ... transfer logic
}
```

Alternatively, add a `lost_found`-style recovery entry when the early-return path is taken, so the user can later claim their tokens after registering.

---

### Proof of Concept

1. User `alice.near` deposits BTC to the bridge-derived address but has **never** called `storage_deposit` on the nBTC contract (account unregistered).
2. Relayer submits the inclusion proof; the bridge verifies it and calls `nbtc.safe_mint(alice.near, 100_000, None)`.
3. Inside `safe_mint`:
   - `internal_deposit(&bridge_id, 100_000)` executes → bridge nBTC balance: `+100_000`, total supply: `+100_000`.
   - `accounts.get(&alice.near)` returns `None`.
   - Function returns `U128(0)`.
4. Alice's nBTC balance: `0`. Bridge nBTC balance: inflated by `100_000`. No `lost_found` entry. No event.
5. Alice's BTC UTXO is recorded as processed in the bridge; she cannot re-submit the deposit proof. Her BTC is locked and her nBTC is undeliverable. [4](#0-3)

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

**File:** contracts/nbtc/src/lib.rs (L158-159)
```rust
        self.token
            .internal_withdraw(&self.bridge_id, burn_amount.into());
```

**File:** contracts/nbtc/src/lib.rs (L341-351)
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
```
