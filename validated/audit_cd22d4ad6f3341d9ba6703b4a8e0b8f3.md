### Title
`safe_mint` Mints nBTC to Bridge Before Checking Recipient Registration, Causing Permanent Fund Loss — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

The `safe_mint` function in the nBTC token contract mints tokens to `bridge_id` **before** verifying that the recipient `account_id` is registered. If the recipient is unregistered, the function returns early with `U128(0)`, leaving the freshly minted nBTC permanently stranded in the bridge's own balance. The user's BTC is already locked on the Bitcoin side, but they receive no nBTC — a stuck-state loss of user funds with no self-recovery path.

---

### Finding Description

In `safe_mint` the execution order is:

1. `self.token.internal_deposit(&self.bridge_id, amount.into())` — unconditionally increases total nBTC supply and credits `bridge_id`.
2. `if self.token.accounts.get(&account_id).is_none() { return PromiseOrValue::Value(U128(0)); }` — silently aborts if the recipient is not registered. [1](#0-0) 

The check comes **after** the mint. When the early-return branch is taken:

- Total nBTC supply has already grown by `amount`.
- `bridge_id` holds those tokens with no mechanism to forward them later.
- The function signals `U128(0)` to the caller (the satoshi-bridge), which may interpret this as "nothing was minted" and take no corrective action.
- If the satoshi-bridge retries the call (a natural response to a zero-return), a second `internal_deposit` fires, minting another `amount` to `bridge_id`. If the account is now registered, the second call succeeds and the user receives `amount` nBTC — but `2 × amount` nBTC now exist against only `1 × amount` of locked BTC, inflating supply.

The analog to the reported Nouns Builder bug is direct: just as `_transferFrom` moved votes from the wrong source (sender instead of sender's delegate), `safe_mint` credits the wrong account (bridge instead of recipient) and the accounting state diverges from reality.

---

### Impact Explanation

**Without bridge retry:** User's BTC is locked on-chain; the equivalent nBTC is minted but stranded in `bridge_id` with no user-accessible recovery path. Requires privileged operator intervention to redistribute or burn the orphaned tokens. Matches: *Medium — stuck bridge state requiring operator intervention.*

**With bridge retry (realistic):** A second `safe_mint` call mints another `amount` to `bridge_id`, then transfers it to the now-registered user. Total nBTC supply = `2 × amount`; total locked BTC = `1 × amount`. This is unbacked supply inflation. Matches: *Critical — unauthorized minting / supply above backed amount.* [2](#0-1) 

---

### Likelihood Explanation

The trigger is a normal user action: depositing BTC while the destination NEAR account is not yet registered in the nBTC contract (storage deposit not paid). This is a common onboarding sequence — a user bridges BTC before interacting with the token contract. No special privilege is required. The satoshi-bridge calls `safe_mint` automatically upon successful deposit verification, so the vulnerable path is reached on every such deposit.

---

### Recommendation

Reverse the order of operations: check registration **before** minting.

```rust
pub fn safe_mint(...) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, "...");

    // Guard FIRST — no tokens are created if the account is absent.
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));
    }

    self.token.internal_deposit(&self.bridge_id, amount.into());
    // ... transfer logic unchanged
}
```

Alternatively, auto-register the account (paying storage from attached deposit) before minting, so the early-return branch is never reached after a successful deposit.

---

### Proof of Concept

```
1. Alice deposits 0.01 BTC to her bridge deposit address.
   Alice's NEAR account `alice.near` has NOT called storage_deposit on nbtc.

2. Relayer submits verify_deposit proof → satoshi-bridge confirms inclusion.

3. satoshi-bridge calls:
     nbtc.safe_mint(account_id="alice.near", amount=1_000_000, msg=None)

4. Inside safe_mint:
     internal_deposit(&bridge_id, 1_000_000)   // total_supply += 1_000_000
                                                // bridge_id balance = 1_000_000
     accounts.get("alice.near") == None         // not registered
     return U128(0)                             // early exit

5. Result:
     - total_supply = 1_000_000 (nBTC minted)
     - alice.near balance = 0   (no nBTC received)
     - bridge_id balance = 1_000_000 (orphaned)
     - Alice's 0.01 BTC is locked on Bitcoin with no NEAR-side recourse.

6. If satoshi-bridge retries after Alice registers:
     internal_deposit(&bridge_id, 1_000_000)   // total_supply = 2_000_000
     ft_transfer("alice.near", 1_000_000)       // alice gets 1_000_000
     // 1_000_000 nBTC still orphaned in bridge_id
     // Supply = 2× backed amount → inflation
``` [3](#0-2)

### Citations

**File:** contracts/nbtc/src/lib.rs (L100-124)
```rust
    #[payable]
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
