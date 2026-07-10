### Title
Unaccounted Storage Staking in `mint_inner` and `burn` Causes Eventual Minting Failure - (File: `contracts/nbtc/src/lib.rs`)

### Summary
The `mint_inner` helper and the `burn` function both call `internal_register_account` to create new token accounts without charging or accounting for the NEAR storage stake required. Over time, as unique accounts accumulate, the nBTC contract's own NEAR balance is silently consumed to cover storage costs. Once exhausted, all future `mint()` calls will fail, permanently blocking nBTC issuance for new depositors.

### Finding Description
Two production paths in `contracts/nbtc/src/lib.rs` call `internal_register_account` without any storage deposit:

**Path 1 — `mint_inner` (called from `mint`):** [1](#0-0) 

Every time the bridge mints tokens to a first-time recipient, `mint_inner` silently registers that account in the `FungibleToken` `accounts` LookupMap. No NEAR is collected from the caller or the recipient to cover this storage cost. The `mint()` function itself carries no `#[payable]` attribute and accepts no attached deposit. [2](#0-1) 

**Path 2 — `burn` relayer registration:** [3](#0-2) 

When a relayer account has never been seen before, `burn` also registers it for free.

By contrast, the `safe_mint` path correctly avoids this problem by returning early when the recipient is not already registered: [4](#0-3) 

### Impact Explanation
Each `internal_register_account` call writes a new entry into the `accounts` LookupMap, consuming approximately 0.00125 NEAR of storage stake from the contract's own balance. Because no storage fee is collected, the contract's NEAR balance is drained proportionally to the number of unique recipients. When the balance falls below the required storage stake, NEAR's runtime will reject further state writes, causing every subsequent `mint()` call to panic. At that point:

- New BTC depositors cannot receive nBTC.
- The bridge's minting pipeline is stuck until an operator manually tops up the contract's NEAR balance.
- In the absence of a recovery path, BTC already sent to deposit addresses may be unclaimable.

This matches the **Medium** impact class: stuck bridge state requiring operator intervention, with potential escalation to Critical if deposited BTC becomes unrecoverable.

### Likelihood Explanation
The bridge is designed for public use. Every unique depositor who has never held nBTC before triggers a free account registration. An attacker can accelerate depletion by generating many unique NEAR accounts and submitting valid BTC deposits to each, or simply by the organic growth of the user base. No privileged access is required beyond submitting a valid deposit proof, which is the normal public entry point.

### Recommendation
Charge a nominal storage fee when registering a new account inside `mint_inner`. The standard NEP-141 pattern is to require recipients to call `storage_deposit` before receiving tokens. If the bridge must auto-register accounts (to avoid failed mints), it should:

1. Compute the storage cost delta before and after `internal_register_account`.
2. Require the bridge caller to attach sufficient NEAR to cover that delta, or maintain a dedicated storage reserve funded at deployment.
3. Alternatively, mirror the `safe_mint` guard: skip minting (and refund the deposit) if the recipient has not pre-registered via `storage_deposit`.

### Proof of Concept

1. Deploy the nBTC contract with a modest NEAR balance (e.g., 5 NEAR).
2. From the bridge account, call `mint()` repeatedly with a new, unique `mint_account_id` each time (each account having never called `storage_deposit`).
3. Observe that each call succeeds and registers a new account at the contract's expense.
4. After ~4,000 unique accounts (≈ 5 NEAR ÷ 0.00125 NEAR/account), the next `mint()` call panics with a storage exhaustion error.
5. All subsequent BTC depositors whose NEAR accounts have never held nBTC are now unable to receive their tokens.

The root cause is the unconditional free registration in `mint_inner`: [5](#0-4) 
and the analogous free registration in `burn`: [6](#0-5)

### Citations

**File:** contracts/nbtc/src/lib.rs (L114-116)
```rust
        if self.token.accounts.get(&account_id).is_none() {
            return PromiseOrValue::Value(U128(0));
        }
```

**File:** contracts/nbtc/src/lib.rs (L126-135)
```rust
    pub fn mint(
        &mut self,
        mint_account_id: AccountId,
        mint_amount: U128,
        protocol_fee: U128,
        relayer_account_id: AccountId,
        relayer_fee: U128,
        post_actions: Option<Vec<PostAction>>,
    ) {
        self.assert_bridge();
```

**File:** contracts/nbtc/src/lib.rs (L160-163)
```rust
        if relayer_fee.0 > 0 {
            if self.token.accounts.get(&relayer_account_id).is_none() {
                self.token.internal_register_account(&relayer_account_id);
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
