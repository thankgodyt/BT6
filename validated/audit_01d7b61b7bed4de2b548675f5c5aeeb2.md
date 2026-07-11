### Title
Silent Zero-Transfer in `safe_mint` Permanently Locks User BTC Deposit When Recipient Account Is Unregistered - (File: contracts/nbtc/src/lib.rs)

### Summary
The `safe_mint` function in the nBTC token contract mints the full deposit amount to the bridge's own balance first, then silently returns `U128(0)` if the recipient NEAR account is not registered — without transferring tokens to the user and without recording the shortfall in `lost_found`. The user's BTC is already locked on-chain (UTXO verified), so no refund path exists. This is the direct analog of the external report's `msg.value`-vs-`amount` minting bug: a wrong variable/path is used in the accounting step, causing the user to receive zero tokens while their deposit is consumed.

### Finding Description

In `contracts/nbtc/src/lib.rs`, `safe_mint` (lines 101–124) executes in this order:

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
    self.token.internal_deposit(&self.bridge_id, amount.into()); // ← mints to bridge

    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));                   // ← silent zero return
    }
    // transfer to user only if registered
    ...
}
``` [1](#0-0) 

Step 1 (`internal_deposit` to `self.bridge_id`) unconditionally increases the bridge's nBTC balance by `amount`. Step 2 checks registration and, if the account is absent, returns `U128(0)` — no transfer, no `lost_found` entry, no revert. The minted tokens remain silently in the bridge's balance.

Contrast this with `mint_inner`, which is used by the privileged `mint` path and **auto-registers** any unregistered account before depositing:

```rust
fn mint_inner(&mut self, account_id: &AccountId, amount: U128) {
    if self.token.accounts.get(account_id).is_none() {
        self.token.internal_register_account(account_id);   // ← auto-register
    }
    self.token.internal_deposit(account_id, amount.into());
    ...
}
``` [2](#0-1) 

`safe_mint` skips this auto-registration entirely. The `lost_found` map, which is populated in `transfer_nbtc_callback` for failed transfers, is never touched by `safe_mint`'s early-return path: [3](#0-2) 

So there is no recovery mechanism for the silently-lost tokens.

### Impact Explanation

- The user's BTC is locked on the Bitcoin side; the deposit UTXO is added to `verified_deposit_utxo` before `safe_mint` is called, blocking any subsequent `request_refund`.
- The user receives `U128(0)` nBTC — a complete loss of their deposit.
- The bridge's nBTC balance is inflated by `amount` without a corresponding user liability, breaking the 1:1 BTC-to-nBTC backing invariant.
- The untracked surplus in the bridge's balance can be consumed by future `burn` calls (withdrawal payouts), effectively allowing other users' withdrawals to be funded by the victim's deposit.

This matches **Critical — Significant loss of user funds** and **Critical — Unauthorized minting / broken backed supply**.

### Likelihood Explanation

Any user who sends BTC to a deposit address derived from a NEAR account that has not yet called `storage_deposit` on the nBTC contract will trigger this path. New users, users migrating from another wallet, or users following an incomplete integration guide are all realistic victims. The entry point is fully unprivileged: the user only needs to send BTC to the bridge deposit address.

### Recommendation

Apply the same auto-registration pattern used in `mint_inner` inside `safe_mint`, before the early-return check:

```rust
// Before checking registration, ensure the account exists:
if self.token.accounts.get(&account_id).is_none() {
    self.token.internal_register_account(&account_id);
}
self.token.internal_deposit(&self.bridge_id, amount.into());
// ... proceed with transfer
```

Alternatively, if intentional non-registration is a valid state, record the undelivered amount in `lost_found` so the user can reclaim it later — mirroring the pattern already used in `transfer_nbtc_callback`.

### Proof of Concept

1. User generates a deposit address from their NEAR account ID (`alice.near`) but has never called `storage_deposit` on the nBTC contract.
2. User sends 0.01 BTC to the deposit address; a relayer submits the inclusion proof to `satoshi-bridge`.
3. Bridge verifies the proof, marks the UTXO in `verified_deposit_utxo`, and calls `nbtc.safe_mint(alice.near, 1_000_000, None)`.
4. Inside `safe_mint`: `self.token.internal_deposit(&self.bridge_id, 1_000_000)` executes — bridge balance increases by 1,000,000 satoshis of nBTC.
5. `self.token.accounts.get(&alice.near).is_none()` → `true` → function returns `U128(0)`.
6. `alice.near` receives 0 nBTC. Their BTC is locked. The UTXO is verified, so `request_refund` is blocked. The 1,000,000 nBTC sits in the bridge's balance, untracked. [4](#0-3)

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

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L61-68)
```rust
        if !promise_success {
            self.data_mut()
                .lost_found
                .entry(account_id.clone())
                .and_modify(|v| *v += amount.0)
                .or_insert(amount.0);
            Event::LostFoundNbtc {
                account_id: &account_id,
```
