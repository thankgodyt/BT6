### Title
Supply/Accounting Failure in `safe_mint`: Tokens Minted to Bridge Before Registration Check, Permanently Stranded on Unregistered Recipient — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

The `safe_mint` function in the nBTC token contract unconditionally mints tokens into `bridge_id`'s balance **before** checking whether the intended recipient account is registered. If the recipient is not registered, the function returns `U128(0)` and exits — but the already-minted tokens remain credited to `bridge_id` with no burn, no rollback, and no `lost_found` entry. This creates a permanent supply/accounting divergence: total nBTC supply increases while the user receives nothing and their underlying BTC deposit remains locked in the bridge's Bitcoin address.

---

### Finding Description

In `contracts/nbtc/src/lib.rs`, the `safe_mint` function executes in this order:

```rust
// Line 112 — tokens minted to bridge_id UNCONDITIONALLY
self.token.internal_deposit(&self.bridge_id, amount.into());

// Line 114-116 — registration check AFTER minting
if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));  // early return, no burn, no recovery
}
``` [1](#0-0) 

The `internal_deposit` call at line 112 increases both `bridge_id`'s balance and the contract's `total_supply`. The guard at line 114 then discovers the recipient is unregistered and returns `U128(0)` — but the supply mutation has already been committed to state. There is no subsequent `internal_withdraw`, no `burn`, and no insertion into the `lost_found` map (which exists in the bridge contract's `transfer_nbtc_callback` but is never reached here). [2](#0-1) 

By contrast, the sibling `mint` function uses `mint_inner`, which auto-registers the account before depositing, so it never leaves tokens stranded:

```rust
fn mint_inner(&mut self, account_id: &AccountId, amount: U128) {
    if self.token.accounts.get(account_id).is_none() {
        self.token.internal_register_account(account_id);  // register first
    }
    self.token.internal_deposit(account_id, amount.into()); // then deposit
    ...
}
``` [3](#0-2) 

`safe_mint` inverts this order: it deposits first, checks registration second, and provides no recovery path on failure.

---

### Impact Explanation

When `safe_mint` is called for an unregistered recipient:

1. `total_supply` increases by `amount` — nBTC is minted into existence.
2. The minted tokens sit in `bridge_id`'s balance indefinitely.
3. The user's BTC deposit is already locked in the bridge's Bitcoin address (the deposit was verified before minting was triggered).
4. The user receives zero nBTC.
5. No automatic recovery exists: `safe_mint` returns `U128(0)` to the bridge, but the bridge has no in-scope mechanism to burn the stranded tokens or credit `lost_found` from this path.

This constitutes **permanent locking of user funds** (BTC locked on-chain, nBTC stranded in bridge account) and a **supply/accounting divergence** where circulating supply exceeds tokens actually held by users. Impact: **Critical** — significant loss and permanent locking of user funds.

---

### Likelihood Explanation

NEAR's NEP-141 standard requires recipients to call `storage_deposit` on the token contract before they can hold a balance. Any user who deposits BTC without first registering on the nBTC contract — a common omission for new users unfamiliar with NEAR storage mechanics — will trigger this path. The entry point is fully unprivileged: any BTC sender can reach `safe_mint` by submitting a valid deposit proof to the bridge. No special role or leaked key is required.

---

### Recommendation

Invert the order of operations in `safe_mint` to match `mint_inner`: check (or perform) account registration **before** calling `internal_deposit`. If auto-registration is not desired, the function should either:

- Return early (with no state change) before minting when the account is unregistered, or
- Burn the minted tokens (`internal_withdraw(&self.bridge_id, amount)`) before returning `U128(0)`, or
- Insert the stranded amount into the bridge's `lost_found` map so the user can later claim it.

---

### Proof of Concept

1. User Alice sends 1 BTC to the bridge deposit address.
2. A relayer submits the transaction and Merkle proof; the bridge verifies it and calls `nbtc.safe_mint(alice.near, 100_000_000, None)`.
3. Inside `safe_mint`: `internal_deposit(&bridge_id, 100_000_000)` executes — `bridge_id` balance increases by 1 BTC-equivalent, `total_supply` increases by 1 BTC-equivalent.
4. `accounts.get(&alice.near)` returns `None` (Alice never called `storage_deposit` on the nBTC contract).
5. `safe_mint` returns `PromiseOrValue::Value(U128(0))` — no transfer, no burn, no `lost_found` entry.
6. Alice's BTC remains locked in the bridge's Bitcoin address. Alice holds 0 nBTC. 1 BTC-equivalent of nBTC is permanently stranded in `bridge_id`'s balance, inflating total supply above the backed amount. [4](#0-3)

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

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L54-72)
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
```
