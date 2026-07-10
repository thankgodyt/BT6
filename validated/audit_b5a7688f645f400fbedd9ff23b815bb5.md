### Title
Premature Total-Supply Inflation in `safe_mint` When Recipient Account Is Unregistered — (File: contracts/nbtc/src/lib.rs)

---

### Summary

The `safe_mint` function in the nBTC token contract unconditionally mints tokens to `bridge_id` (increasing the global total supply) **before** checking whether the intended recipient account is registered. When the recipient is unregistered the function returns `U128(0)` without burning the already-minted tokens, permanently inflating the circulating supply without delivering nBTC to the user and without any on-contract accounting correction.

---

### Finding Description

In `contracts/nbtc/src/lib.rs`, `safe_mint` executes as follows:

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
    self.token.internal_deposit(&self.bridge_id, amount.into()); // ← total supply +amount HERE

    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));                   // ← early return, no burn
    }
    // ...transfer to account_id...
}
``` [1](#0-0) 

`internal_deposit` on the underlying `FungibleToken` increases `total_supply` and credits `bridge_id`. The registration check on line 114 comes **after** this mutation. When the check fails the function returns `U128(0)` synchronously — no `internal_withdraw` is called, no burn event is emitted, and no `lost_found` entry is created. The minted tokens remain in `bridge_id`'s balance and the total supply is permanently higher than the amount of nBTC actually held by users. [2](#0-1) 

The `burn` function, which could restore the invariant, is restricted to the bridge caller via `assert_bridge()` and is never invoked automatically on a `U128(0)` return from `safe_mint`. [3](#0-2) 

The `lost_found` accounting in `token_transfer.rs` only covers failures in `transfer_nbtc_callback` (the ft_transfer path), not the `safe_mint` early-return path. [4](#0-3) 

---

### Impact Explanation

Every time a deposit proof is submitted for a user whose NEAR account is not registered on the nBTC contract, the total supply of nBTC increases by the deposited amount while the user receives zero tokens. The user's BTC is locked inside the bridge's UTXO set (the deposit UTXO is marked verified), and the inflated `bridge_id` balance is not tracked anywhere as a liability. Over repeated occurrences this silently breaks the 1:1 BTC-backing invariant: more nBTC exists on-chain than BTC is redeemable. This matches the **Medium** allowed impact: *permanent burning below backed supply / broken callback rollback / stuck bridge state requiring operator intervention*.

---

### Likelihood Explanation

The trigger condition — a user sending BTC to a deposit address before registering their NEAR account on the nBTC contract — is a realistic and common onboarding mistake. Registration requires a separate `storage_deposit` call that new users frequently omit. Any public relayer can then submit the deposit proof, causing `safe_mint` to be called with the unregistered account. No privileged access is required; the attacker-controlled input is simply the deposit transaction itself.

---

### Recommendation

Move the registration check **before** `internal_deposit`, or add an `internal_withdraw` (burn) on the early-return path:

```rust
// Option A – check first, mint only if registered
if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));
}
self.token.internal_deposit(&self.bridge_id, amount.into());
```

```rust
// Option B – burn on early return
self.token.internal_deposit(&self.bridge_id, amount.into());
if self.token.accounts.get(&account_id).is_none() {
    self.token.internal_withdraw(&self.bridge_id, amount.into());
    return PromiseOrValue::Value(U128(0));
}
```

Additionally, add documentation clarifying what token type `safe_mint` operates on and what the contract's invariant is when the recipient is unregistered, analogous to the recommendation in the original report.

---

### Proof of Concept

1. User generates a deposit address (derived from their NEAR account ID) and sends 0.01 BTC to it.
2. User has **not** called `storage_deposit` on the nBTC contract, so their account is unregistered.
3. A public relayer calls `verify_deposit(proof_args)` on the satoshi-bridge.
4. The bridge, after verifying the Merkle proof, calls `nbtc.safe_mint(user_account, 1_000_000, None)`.
5. Inside `safe_mint`: `internal_deposit(&bridge_id, 1_000_000)` executes — `total_supply` increases by 1 000 000 satoshis.
6. `accounts.get(&user_account).is_none()` → `true` → returns `U128(0)`.
7. No burn is performed. `bridge_id` now holds 1 000 000 extra nBTC with no corresponding user liability tracked.
8. The deposit UTXO is marked verified; the user cannot request a refund via the normal deposit path.
9. Result: total nBTC supply exceeds the BTC held by the bridge by 1 000 000 satoshis; user's BTC is permanently locked without receiving nBTC. [1](#0-0)

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
