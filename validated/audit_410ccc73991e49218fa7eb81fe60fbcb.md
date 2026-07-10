### Title
Silent Return Instead of Revert in `safe_mint` Leaves Tokens Permanently Stuck in Bridge — (`File: contracts/nbtc/src/lib.rs`)

### Summary

In `contracts/nbtc/src/lib.rs`, the `safe_mint` function mints tokens to `bridge_id` via `internal_deposit` **before** checking whether the recipient account is registered. If the account is unregistered, the function silently returns `U128(0)` instead of reverting. The already-minted tokens remain permanently stuck in `bridge_id`, and the caller (the bridge) receives a zero return value with no panic — leaving the bridge's accounting in an inconsistent state.

### Finding Description

`safe_mint` executes in this order: [1](#0-0) 

```rust
self.token.internal_deposit(&self.bridge_id, amount.into());   // tokens minted here

if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));                      // silent return, no revert
}
```

`internal_deposit` increases `bridge_id`'s balance and the total supply. The subsequent unregistered-account check at line 114 then returns `U128(0)` **without panicking**, so the deposit is never rolled back. The tokens are now credited to `bridge_id` with no path to the intended recipient.

By contrast, the `mint` function calls `mint_inner`, which auto-registers the account before depositing: [2](#0-1) 

`safe_mint` deliberately skips that auto-registration but fails to revert when the account is absent.

### Impact Explanation

The bridge design invariant documented in the wiki states that UTXOs are marked verified **before** cross-contract calls to prevent re-entrancy. This means that by the time `safe_mint` is invoked, the deposit UTXO is already recorded as consumed. If `safe_mint` returns `U128(0)` instead of panicking:

- The UTXO is permanently marked verified — the user cannot refund.
- The user receives zero nBTC.
- Tokens equal to the deposit amount are minted into `bridge_id` with no mechanism to recover them to the user.
- Total supply is inflated relative to user-held supply, breaking the backed-supply invariant.

This matches the **Medium** impact class: *broken callback rollback / stuck bridge state requiring operator intervention*, and *permanent burning below backed supply*.

### Likelihood Explanation

Any user who deposits BTC without first calling `storage_deposit` on the nBTC token contract to register their NEAR account will trigger this path. This is a realistic omission — the deposit flow does not enforce prior registration, and the bridge's `verify_deposit` path does not check nBTC registration before proceeding.

### Recommendation

Move the registration check **before** `internal_deposit`, or replace the silent return with a `require!` that panics and reverts the entire call:

```rust
// Option A: check first, revert loudly
require!(
    self.token.accounts.get(&account_id).is_some(),
    "safe_mint: recipient account not registered in nBTC"
);
self.token.internal_deposit(&self.bridge_id, amount.into());
```

A panic here will revert `internal_deposit` and propagate failure back to the bridge, allowing the bridge to handle the error correctly rather than silently accepting a zero return.

### Proof of Concept

1. Deploy nBTC token contract and bridge contract.
2. Do **not** call `storage_deposit` for `alice.near` on the nBTC contract.
3. Alice sends BTC; relayer calls `verify_deposit` on the bridge.
4. Bridge marks the deposit UTXO as verified, then calls `safe_mint(alice.near, amount, None)`.
5. `safe_mint` executes `internal_deposit(&bridge_id, amount)` — bridge_id balance increases by `amount`.
6. `self.token.accounts.get(&alice.near)` returns `None`.
7. Function returns `PromiseOrValue::Value(U128(0))` — no panic, no revert.
8. Alice's UTXO is permanently consumed; she holds 0 nBTC; `amount` satoshis worth of nBTC are stuck in `bridge_id`. [3](#0-2)

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

**File:** contracts/nbtc/src/lib.rs (L341-345)
```rust
    fn mint_inner(&mut self, account_id: &AccountId, amount: U128) {
        if self.token.accounts.get(account_id).is_none() {
            self.token.internal_register_account(account_id);
        }
        self.token.internal_deposit(account_id, amount.into());
```
