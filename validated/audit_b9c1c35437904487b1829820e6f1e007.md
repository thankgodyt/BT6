### Title
`safe_mint` Mints nBTC to Bridge Before Checking User Registration, Permanently Stranding Deposited Funds — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

`safe_mint` in the nBTC token contract unconditionally mints `amount` tokens into the bridge's own balance **before** checking whether the recipient account is registered. When the recipient is unregistered the function returns `U128(0)` and exits, leaving the freshly-minted tokens permanently stranded in the bridge's balance. The bridge's callback receives `0` and cannot credit the user, while the BTC UTXO has already been marked verified and is ineligible for refund.

---

### Finding Description

In `contracts/nbtc/src/lib.rs`, `safe_mint` executes in this order:

```rust
// Step 1 – tokens are minted into the bridge's own balance unconditionally
self.token.internal_deposit(&self.bridge_id, amount.into());

// Step 2 – only NOW is registration checked
if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));   // early exit; minted tokens stay in bridge
}
``` [1](#0-0) 

When `account_id` is unregistered the function returns the synchronous value `U128(0)`. The `amount` tokens that were deposited into `self.bridge_id` at line 112 are **not reversed**; they remain in the bridge's nBTC balance indefinitely. The bridge's mint callback receives `0` as the reported minted amount and has no way to distinguish "nothing was minted" from "tokens were minted but not forwarded", so no `lost_found` entry is created for the user.

The analog to the tBTC report is direct: just as `provideFundingECDSAFraudProof` attempted to burn `address(this).balance` which was zero because the payment flow had changed, `safe_mint` here performs a real token issuance (`internal_deposit`) into an account whose balance is then silently abandoned — a supply-accounting action that operates on funds the intended recipient will never receive.

---

### Impact Explanation

- The nBTC total supply is inflated by `amount` with no corresponding user balance.
- The bridge's nBTC balance grows by `amount`; those tokens are indistinguishable from legitimately-held bridge funds (protocol fees, relayer fees) and can be spent by the bridge for unrelated purposes.
- The depositor's BTC UTXO is marked verified on-chain and is blocked from the refund path (`verified_deposit_utxo` set), so the user cannot recover their BTC either.
- Net result: **permanent, irrecoverable loss of the user's deposited BTC with no nBTC issued to them** — matching the "significant loss or permanent locking of user funds" critical impact class.

---

### Likelihood Explanation

Any NEAR account that has not called `storage_deposit` on the nBTC contract is unregistered. A first-time depositor who sends BTC before registering their nBTC storage slot triggers this path. No privileged access is required; the condition is reachable by any ordinary bridge user. The nBTC contract does not auto-register accounts, so the scenario is realistic in normal usage.

---

### Recommendation

Move the registration check **before** `internal_deposit`. If the account is unregistered, either auto-register it (charging the bridge for storage) or revert the call so the bridge's mint callback can place the amount in `lost_found` with the correct value:

```rust
pub fn safe_mint(...) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, "...");

    // Check registration BEFORE minting
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));
    }

    self.token.internal_deposit(&self.bridge_id, amount.into());
    // ... transfer / ft_transfer_call as before
}
```

Alternatively, if early-exit semantics must be preserved, the bridge's mint callback must treat a `U128(0)` return as "amount was minted to bridge but not forwarded" and record the full `amount` in `lost_found`.

---

### Proof of Concept

1. Alice deposits 0.01 BTC to her bridge deposit address.
2. Alice has never called `storage_deposit` on the nBTC contract — her account is unregistered.
3. A relayer submits the Merkle inclusion proof; the bridge verifies it and calls `safe_mint(alice, 1_000_000, None)` on the nBTC contract.
4. `internal_deposit(&bridge_id, 1_000_000)` executes — bridge's nBTC balance: `+1_000_000`.
5. `accounts.get(&alice)` returns `None` → function returns `U128(0)`.
6. Bridge's mint callback receives `0`; no `lost_found` entry is written for Alice.
7. Alice's BTC UTXO is now in `verified_deposit_utxo`; `request_refund` is blocked.
8. Alice holds 0 nBTC. Her 0.01 BTC is permanently locked. The bridge holds 1 000 000 extra nBTC satoshis that can be silently consumed as protocol or relayer fees. [2](#0-1) [3](#0-2)

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

**File:** contracts/satoshi-bridge/src/lib.rs (L140-141)
```rust
    pub lost_found: IterableMap<AccountId, u128>,
    pub acc_collected_protocol_fee: u128,
```
