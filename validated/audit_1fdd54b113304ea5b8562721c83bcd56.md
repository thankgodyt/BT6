### Title
`safe_mint` Mints Tokens to Bridge Before Checking Recipient Registration, Causing Irrecoverable Token Lockup on Unregistered Accounts — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

The `safe_mint` function in the nBTC token contract mints tokens to `bridge_id` **before** verifying that the recipient account is registered for nBTC storage. If the recipient is unregistered, the function returns `U128(0)` without burning the already-minted tokens, leaving them permanently locked in `bridge_id` with no recovery path within the nBTC contract itself.

---

### Finding Description

In `contracts/nbtc/src/lib.rs`, `safe_mint` (lines 101–124) executes in this order:

1. **Mints `amount` tokens to `bridge_id`** via `internal_deposit` (line 112) — a permanent state change in the nBTC contract.
2. **Checks if `account_id` is registered** (line 114).
3. **If not registered, returns `U128(0)` early** (lines 115–116) — without burning the already-minted tokens and without adding them to `lost_found`. [1](#0-0) 

This is the direct analog to the reported vulnerability: just as `mintWithPermit`/`depositWithPermit` calls `permit()` on stETH (which has no `permit` function) causing a revert, `safe_mint` assumes the recipient account is storage-registered (the NEAR equivalent of "has the required interface"), silently fails when it is not, and leaves the protocol in a broken intermediate state.

In NEAR's asynchronous cross-contract call model, the nBTC contract's state change — minting tokens to `bridge_id` — is **finalized** the moment `safe_mint` returns. The bridge's callback cannot undo this by panicking; a panic in the callback only reverts the bridge's own state changes, not the nBTC contract's. The bridge would need to issue a separate `burn` cross-contract call to clean up, which is not present in `safe_mint` itself.

The `verify_deposit_v2` documentation explicitly states the safe-deposit path "reverts the whole transaction if minting fails (no lost & found)": [2](#0-1) 

But this "revert" only applies to the bridge's own callback state. The nBTC tokens already minted to `bridge_id` are not reverted, and `safe_mint` provides no `burn` or `lost_found` fallback for this case. [3](#0-2) 

---

### Impact Explanation

If the bridge's callback panics on receiving `U128(0)` (the documented "revert" behavior), the nBTC tokens minted to `bridge_id` in step 1 remain permanently there. The user's BTC is locked in the bridge's custody, and they receive zero nBTC. There is no `lost_found` entry and no recovery path within the nBTC contract. This constitutes a **permanent loss of user funds** — the user's BTC is irretrievably locked.

---

### Likelihood Explanation

A user triggers this by sending BTC with a `safe_deposit` message (e.g., via Omni Bridge integration) targeting a NEAR account that has not yet called `storage_deposit` on the nBTC contract. This is a realistic scenario: users initiating cross-chain deposits may not know they must pre-register nBTC storage on the destination account before the deposit is processed. Any relayer submitting `verify_deposit_v2` with `deposit_msg.safe_deposit = Some(..)` for such an account will trigger this path. [4](#0-3) 

---

### Recommendation

Move the registration check **before** `internal_deposit`, so no tokens are minted if the recipient is unregistered:

```rust
pub fn safe_mint(...) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, "...");

    // Check registration BEFORE minting
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));
    }

    self.token.internal_deposit(&self.bridge_id, amount.into());
    // ... rest of transfer logic
}
```

Alternatively, if minting to `bridge_id` first is required, add an explicit `internal_withdraw` from `bridge_id` in the early-return path to undo the mint before returning `U128(0)`.

---

### Proof of Concept

1. User sends BTC on-chain with a `safe_deposit` deposit message targeting NEAR account `alice.near`, which has **not** called `storage_deposit` on the nBTC contract.
2. Relayer calls `verify_deposit_v2` with `deposit_msg.safe_deposit = Some(..)`. Bridge verifies the BTC proof and calls `safe_mint(alice.near, amount, msg)` on the nBTC contract.
3. `safe_mint` executes `self.token.internal_deposit(&self.bridge_id, amount.into())` — nBTC tokens are now minted to `bridge_id`. [5](#0-4) 
4. `safe_mint` checks `self.token.accounts.get(&alice.near)` — returns `None` (unregistered). [6](#0-5) 
5. `safe_mint` returns `U128(0)` with no burn, no `lost_found` entry.
6. Bridge's callback receives `U128(0)`, interprets it as failure, and panics to "revert." The bridge's own state changes are rolled back, but the nBTC contract's `internal_deposit` to `bridge_id` is **not** rolled back.
7. Result: User's BTC is locked in the bridge; `amount` nBTC is permanently stuck in `bridge_id`; no recovery path exists.

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L54-58)
```rust
    /// * `Some(..)` — safe deposit (e.g. Omni Bridge): charges no fee, reverts the whole
    ///   transaction if minting fails (no lost & found), and the caller must attach NEAR for
    ///   the user's token storage (see `required_balance_for_safe_deposit`).
    /// * `None` — standard deposit: charges the deposit fee, pays the user's storage, and
    ///   routes mint failures to lost & found.
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L81-101)
```rust
        if deposit_msg.safe_deposit.is_some() {
            self.internal_safe_verify_deposit_entry(
                deposit_msg,
                tx_bytes.0,
                vout,
                proof.tx_block_blockhash,
                proof.tx_index,
                proof.merkle_proof,
                coinbase_proof,
            )
        } else {
            self.internal_verify_deposit_entry(
                deposit_msg,
                tx_bytes.0,
                vout,
                proof.tx_block_blockhash,
                proof.tx_index,
                proof.merkle_proof,
                coinbase_proof,
            )
        }
```
