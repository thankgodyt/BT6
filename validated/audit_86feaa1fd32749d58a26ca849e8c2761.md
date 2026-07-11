### Title
Tokens Permanently Stranded in Bridge Account on Unregistered Recipient in `safe_mint` — (File: `contracts/nbtc/src/lib.rs`)

### Summary
`safe_mint` in the nBTC token contract mints tokens to the bridge's own account (`bridge_id`) **before** checking whether the intended recipient is registered. If the recipient is not registered, the function returns early with `U128(0)`, leaving the freshly minted nBTC permanently stranded in `bridge_id` with no recovery path. The corresponding BTC deposit remains locked in the bridge's UTXO set.

### Finding Description

In `contracts/nbtc/src/lib.rs`, `safe_mint` executes `internal_deposit` to `bridge_id` unconditionally at line 112, then checks registration at line 114:

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
    self.token.internal_deposit(&self.bridge_id, amount.into()); // ← tokens minted here

    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));                   // ← early return, tokens stranded
    }
    // transfer to user only if registered
    ...
}
``` [1](#0-0) 

When `account_id` is not registered in the nBTC token contract:

1. `internal_deposit(&self.bridge_id, amount)` increases `bridge_id`'s balance and the total supply by `amount`.
2. The function returns `PromiseOrValue::Value(U128(0))` — no transfer to the user occurs.
3. There is no subsequent burn, refund, or recovery call. The minted tokens remain in `bridge_id` indefinitely.
4. The BTC UTXO that funded the deposit is marked as verified and consumed by the bridge, so it cannot be refunded via the normal refund path either.

The `burn` function withdraws from `bridge_id`:

```rust
pub fn burn(&mut self, burn_account_id: AccountId, burn_amount: U128, ...) {
    self.assert_bridge();
    self.token.internal_withdraw(&self.bridge_id, burn_amount.into());
    ...
}
``` [2](#0-1) 

The stranded tokens inflate `bridge_id`'s balance, which means future legitimate burns can silently consume tokens that were never properly credited to any user — breaking the 1:1 BTC-to-nBTC backing invariant.

### Impact Explanation

- **User's BTC is permanently locked**: the deposit UTXO is consumed by the bridge and cannot be refunded.
- **nBTC total supply is inflated**: tokens are minted but never delivered, so total supply exceeds the sum of all user balances.
- **Bridge backing invariant broken**: `bridge_id` accumulates phantom nBTC that can be burned against future withdrawals, enabling the bridge to release BTC it does not owe.

This matches: *Critical — Significant loss, theft, destruction, or permanent locking of user or protocol funds* and *Critical — Unauthorized minting/unlocking of nBTC or underlying BTC*.

### Likelihood Explanation

Any user who:
1. Sends BTC to a bridge deposit address, and
2. Has not previously called `storage_deposit` on the nBTC contract to register their NEAR account

will trigger this path. NEAR's NEP-141 standard requires explicit storage registration; new or infrequent users commonly omit this step. No privileged access is required — the deposit proof submission is fully public.

### Recommendation

Move the registration check **before** `internal_deposit`. If the account is not registered, either:
- Reject the mint and allow the deposit to be refunded, or
- Auto-register the account (paying storage from attached deposit), then proceed.

```rust
// Check registration BEFORE minting
if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));
}
self.token.internal_deposit(&self.bridge_id, amount.into());
// ... transfer to user
```

### Proof of Concept

1. User Alice sends 0.01 BTC to a bridge deposit address derived from her NEAR account `alice.near`.
2. Alice has never called `storage_deposit` on the nBTC contract, so `alice.near` is not registered.
3. A relayer submits the BTC transaction and Merkle proof via `verify_deposit_v2`. The bridge validates the proof and calls `safe_mint(alice.near, 1_000_000, None)` on the nBTC contract.
4. `internal_deposit(&bridge_id, 1_000_000)` executes — bridge_id's nBTC balance increases by 1,000,000 satoshis-worth of nBTC; total supply increases by the same.
5. `self.token.accounts.get(&alice.near)` returns `None` → function returns `U128(0)`.
6. Alice receives 0 nBTC. Her BTC UTXO is marked as `verified_deposit_utxo` and cannot be refunded.
7. The 1,000,000 nBTC sits in `bridge_id`. A future withdrawal by any user burns from `bridge_id`, consuming Alice's phantom tokens and releasing BTC that was never legitimately withdrawn — breaking the backing invariant. [3](#0-2)

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
