Looking at the `safe_mint` function in `contracts/nbtc/src/lib.rs`, I can identify a direct analog to the external report's vulnerability class: **state mutation before validation**, where an irreversible action is taken before a critical guard check, causing permanent fund loss.

---

### Title
`safe_mint` Mints nBTC to Bridge Before Checking Recipient Registration, Permanently Locking User Funds - (File: `contracts/nbtc/src/lib.rs`)

### Summary
In `safe_mint`, `internal_deposit` mints nBTC to `bridge_id` **before** checking whether the recipient account is registered. If the recipient is unregistered, the function silently returns `U128(0)` without transferring the tokens, leaving them permanently locked in the bridge account with no recovery path.

### Finding Description
The `safe_mint` function executes in this order:

```rust
// Step 1: Mint tokens to bridge_id — state is mutated
self.token.internal_deposit(&self.bridge_id, amount.into());

// Step 2: THEN check if recipient is registered
if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));  // silent early return, tokens stuck
}
``` [1](#0-0) 

The guard check (recipient registration) comes **after** the irreversible state mutation (minting). When `account_id` is not registered, the function returns `U128(0)` — the nBTC total supply has already increased, the bridge's balance holds the minted tokens, but no transfer to the user ever occurs and no `lost_found` entry is created.

This is the direct analog to the external report: in the report, `userStake` (a zero-initialized memory struct) is compared against `lastGaugeLoss` **before** the real stored value is loaded, causing incorrect slashing. Here, `internal_deposit` mutates state **before** the registration check, causing tokens to be permanently locked.

Contrast with the regular `mint` path, which auto-registers the account before depositing:

```rust
fn mint_inner(&mut self, account_id: &AccountId, amount: U128) {
    if self.token.accounts.get(account_id).is_none() {
        self.token.internal_register_account(account_id);
    }
    self.token.internal_deposit(account_id, amount.into());
``` [2](#0-1) 

`safe_mint` performs neither auto-registration nor a pre-mint guard, making it inconsistent with `mint` and broken for unregistered recipients.

### Impact Explanation
**Critical — Permanent locking of user funds.**

When a user deposits BTC and their NEAR account is not registered for nBTC storage:
1. The relayer submits the deposit proof.
2. The bridge calls `safe_mint(user_account_id, amount, ...)`.
3. `internal_deposit(&self.bridge_id, amount)` increases bridge's nBTC balance and total supply.
4. The registration check fails; the function returns `U128(0)`.
5. The user's BTC is locked in the Bitcoin deposit address; the minted nBTC is stuck in `bridge_id` with no recovery mechanism (no `lost_found` entry, no revert, no refund path).

The nBTC supply is inflated relative to what users actually hold, and the user's BTC is unrecoverable without manual operator intervention.

### Likelihood Explanation
**Medium.** Any user who deposits BTC without first calling `storage_deposit` on the nBTC contract to register their NEAR account triggers this path. New users unfamiliar with NEP-141 storage registration requirements are a realistic population. The `safe_mint` function is specifically described as used by integrations (e.g., Omni Bridge), but the bridge contract can call it for any deposit flow where the recipient may not be pre-registered.

### Recommendation
Perform the registration check **before** minting, mirroring the `mint_inner` pattern:

```rust
pub fn safe_mint(...) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, "...");

    // Guard FIRST, before any state mutation
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));
    }

    self.token.internal_deposit(&self.bridge_id, amount.into());
    // ... transfer logic
}
```

Alternatively, revert (`require!`) if the account is unregistered to guarantee the atomicity that `safe_mint` is documented to provide.

### Proof of Concept
1. User sends BTC to the bridge deposit address derived from their `DepositMsg`.
2. User does **not** call `storage_deposit` on the nBTC contract (account unregistered).
3. Relayer submits `verify_deposit` with a valid Merkle proof.
4. Bridge calls `safe_mint(user.near, 100_000_000, None)`.
5. `internal_deposit(&bridge_id, 100_000_000)` executes — bridge nBTC balance +100_000_000, total supply +100_000_000.
6. `self.token.accounts.get(&user.near).is_none()` → `true`.
7. Function returns `U128(0)`. No transfer. No `lost_found` entry.
8. User's BTC is locked. 100_000_000 nBTC is permanently stuck in `bridge_id`. [3](#0-2)

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
