### Title
Silent nBTC Token Loss in `safe_mint` When Recipient Account Is Unregistered — (File: contracts/nbtc/src/lib.rs)

---

### Summary

The `safe_mint` function in the nBTC token contract mints tokens to the bridge's own account **before** checking whether the intended recipient is registered. If the recipient is unregistered, the function silently returns `U128(0)` and exits, leaving the freshly minted tokens permanently stranded in the bridge's nBTC balance with no on-contract recovery path.

---

### Finding Description

In `contracts/nbtc/src/lib.rs`, `safe_mint` executes in this order:

1. **Mint to bridge** — `self.token.internal_deposit(&self.bridge_id, amount.into())` (line 112) unconditionally increases the bridge's nBTC balance by `amount`.
2. **Check recipient registration** — `if self.token.accounts.get(&account_id).is_none()` (line 114).
3. **Silent early return** — `return PromiseOrValue::Value(U128(0))` (line 115) if the recipient has no storage account. [1](#0-0) 

The tokens minted in step 1 are never transferred to the user and never burned. They accumulate silently in the bridge's nBTC balance. The `lost_found` recovery map used elsewhere in the contract (populated in `transfer_nbtc_callback` at lines 62–68) is **not** invoked here, so there is no on-chain path for the user to reclaim their tokens. [2](#0-1) 

This is the direct analog of the Liquity `_requireValidRecipient` class: a data-validation restriction on the token recipient that produces an unexpected, harmful result — instead of reverting cleanly, the contract silently succeeds while the user's value is lost.

---

### Impact Explanation

A depositor whose NEAR account is not registered in the nBTC contract will have their BTC locked in the bridge and will receive zero nBTC. The minted tokens inflate the bridge's nBTC balance with no recovery mechanism inside `safe_mint`. At minimum this is a stuck-bridge-state requiring operator intervention; in practice, without an operator-side recovery path, the user's deposit is permanently lost.

Matches allowed impact: **Medium — stuck bridge state requiring operator intervention / harmful smart-contract behavior without direct theft.**

---

### Likelihood Explanation

Any bridge user who deposits BTC before completing the NEP-141 storage-registration step triggers this path. New users unfamiliar with NEAR's storage model are a realistic population. The bridge calls `safe_mint` on behalf of the depositor; neither the relayer nor the bridge itself validates registration before invoking the function.

---

### Recommendation

- Reverse the order of operations: check recipient registration **before** calling `internal_deposit`. If unregistered, either revert with a clear error or auto-register the account.
- Alternatively, if `safe_mint` must mint to the bridge first, any `U128(0)` return path must record the stranded amount in `lost_found` so the user can later reclaim it, consistent with the pattern already used in `transfer_nbtc_callback`.

---

### Proof of Concept

1. Alice deposits BTC to the bridge specifying `alice.near` as her NEAR recipient.
2. Alice has not called `storage_deposit` on the nBTC contract, so `self.token.accounts.get(&alice.near)` returns `None`.
3. The bridge calls `safe_mint(alice.near, amount, None)`.
4. Line 112 executes: `amount` nBTC is minted into the bridge's own nBTC balance.
5. Line 114 evaluates to `true` (account absent).
6. Line 115 returns `U128(0)` — no transfer, no `lost_found` entry, no event for Alice.
7. Alice's BTC is locked in the bridge; she holds zero nBTC; the bridge's nBTC balance is silently inflated by `amount` with no on-chain recovery path. [3](#0-2)

### Citations

**File:** contracts/nbtc/src/lib.rs (L61-68)
```rust
        bridge_id: AccountId,
        name: String,
        symbol: String,
        icon: Option<String>,
        decimals: u8,
    ) -> Self {
        require!(!env::state_exists(), "Already initialized");
        let mut contract = Self {
```

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
