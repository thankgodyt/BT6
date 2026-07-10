### Title
Minted nBTC Permanently Stuck in Bridge Balance When Recipient Account Is Unregistered — (File: `contracts/nbtc/src/lib.rs`)

### Summary
`safe_mint` unconditionally mints the full deposit amount into the bridge's own nBTC balance before checking whether the recipient is registered. When the recipient is not registered, the function returns `U128(0)` and exits, leaving the minted tokens stranded in the bridge's nBTC account with no burn-back or recovery path inside the nBTC contract.

### Finding Description
In `contracts/nbtc/src/lib.rs`, `safe_mint` executes in this order:

1. `self.token.internal_deposit(&self.bridge_id, amount.into())` — unconditionally mints `amount` nBTC into the bridge's own token balance.
2. `if self.token.accounts.get(&account_id).is_none() { return PromiseOrValue::Value(U128(0)); }` — if the recipient has never called `storage_deposit` on the nBTC contract, the function returns immediately.
3. The minted tokens remain in `bridge_id`'s nBTC balance. There is no `internal_withdraw` (burn-back), no `lost_found` entry, and no other recovery hook inside the nBTC contract.

This is structurally identical to the reported vulnerability class: a value is accumulated into a pool (the bridge's nBTC balance) during a period when the intended recipient is "empty" (unregistered), and that accumulated value becomes unrecoverable by the rightful owner.

The bridge contract's `lost_found` map (populated in `transfer_nbtc_callback` for failed `ft_transfer` calls) does **not** cover the `safe_mint` path, because `safe_mint` never reaches `ft_transfer` when the account is absent — it returns `U128(0)` synchronously before any transfer is attempted.

### Impact Explanation
A user who deposits BTC on-chain but has not yet registered their account in the nBTC contract (via `storage_deposit`) will have their deposit amount minted into the bridge's nBTC balance and permanently inaccessible. Their BTC is locked in the bridge's UTXO set; they receive zero nBTC; and no on-chain path exists within the nBTC contract to recover the minted tokens. This constitutes a permanent, irreversible loss of user funds — matching the **Critical / Medium** stuck-funds impact class.

### Likelihood Explanation
NEP-141 storage registration is a separate, explicit step that many users omit, especially when interacting via a relayer or a third-party front-end that does not pre-register the recipient. Any first-time depositor who has not called `storage_deposit` on the nBTC contract triggers this path. The condition is reachable by any unprivileged NEAR account with no special access required.

### Recommendation
Inside `safe_mint`, if the recipient account is not registered, burn the already-minted tokens back before returning:

```rust
if self.token.accounts.get(&account_id).is_none() {
    self.token.internal_withdraw(&self.bridge_id, amount.into()); // burn back
    return PromiseOrValue::Value(U128(0));
}
```

Alternatively, record the amount in a per-account recovery map (analogous to `lost_found`) so the user can claim their nBTC after registering storage.

### Proof of Concept

1. Alice deposits BTC to her bridge-derived address on-chain.
2. A relayer calls `verify_deposit` on the bridge; the bridge verifies the Merkle proof and calls `safe_mint(alice.near, 100_000, None)` on the nBTC contract.
3. `safe_mint` executes `internal_deposit(&bridge_id, 100_000)` — 100 000 sat-worth of nBTC is minted into the bridge's own nBTC balance.
4. `self.token.accounts.get(&alice.near)` returns `None` (Alice never called `storage_deposit`).
5. `safe_mint` returns `PromiseOrValue::Value(U128(0))`.
6. The 100 000 nBTC sit in the bridge's nBTC balance. Alice's BTC is locked in the bridge UTXO set. No `lost_found` entry is created. No burn occurs.
7. Alice has permanently lost her deposit with no on-chain recovery path. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** contracts/satoshi-bridge/src/lib.rs (L140-141)
```rust
    pub lost_found: IterableMap<AccountId, u128>,
    pub acc_collected_protocol_fee: u128,
```
