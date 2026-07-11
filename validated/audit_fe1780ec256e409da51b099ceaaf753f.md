### Title
`safe_mint` Inflates `total_supply` Without Delivering Tokens When Recipient Is Unregistered — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

In `contracts/nbtc/src/lib.rs`, the `safe_mint` function unconditionally calls `internal_deposit` to mint tokens into the bridge's own balance before checking whether the recipient account is registered. If the recipient is unregistered, the function returns `U128(0)` without transferring tokens and without panicking. This silently inflates `total_supply` while leaving the minted tokens stranded in the bridge's balance and the user without their nBTC.

---

### Finding Description

`safe_mint` (lines 101–124) executes in this order:

1. **Line 112** — `self.token.internal_deposit(&self.bridge_id, amount.into())` is called unconditionally. `internal_deposit` is the NEP-141 standard's authoritative mint path: it increases both the bridge account's balance **and** `total_supply` by `amount`.

2. **Lines 114–116** — Only *after* minting does the function check whether `account_id` is registered. If not, it returns `PromiseOrValue::Value(U128(0))` — a normal, non-panicking return.

3. **Lines 118–123** — Only if the account *is* registered does the function proceed to `ft_transfer_call` / `ft_transfer`, moving the freshly minted tokens from the bridge to the user. [1](#0-0) 

When the early-return path is taken:
- `total_supply` has already been permanently increased by `amount`.
- The bridge's token balance has been permanently increased by `amount`.
- The user receives nothing.
- No panic is raised, so the satoshi-bridge's callback (which gates on `is_promise_success()`) records the cross-contract call as **successful** and performs no rollback.

This directly contradicts the documented invariant in `CLAUDE.md` that `safe_verify_deposit` / `safe_mint` must **revert the entire transaction if mint fails**. [2](#0-1) 

Compare with `mint_inner`, the standard mint helper, which calls `internal_deposit` only after ensuring the account exists (registering it if necessary), so `total_supply` and user balance always move together: [3](#0-2) 

---

### Impact Explanation

Every invocation of `safe_mint` for an unregistered recipient:

- **Permanently inflates `total_supply`** by `amount` with no corresponding user balance — the nBTC supply is no longer fully backed by locked BTC.
- **Strands user funds**: the depositor's BTC is locked on-chain; they receive zero nBTC and have no on-chain recourse.
- **Silently succeeds from the bridge's perspective**: the satoshi-bridge callback sees `is_promise_success() == true` and finalises the deposit as complete, closing the UTXO record and preventing any retry.

This matches the allowed Medium impact: *"permanent burning below backed supply, broken callback rollback, or stuck bridge state requiring operator intervention."*

---

### Likelihood Explanation

The trigger condition — a recipient account that has not yet called `storage_deposit` on the nbtc contract — is a routine NEAR onboarding scenario. Any user who generates a deposit address before registering their account, or who uses an account that was never registered, will hit this path. No special privilege is required; the attacker-controlled input is simply the `DepositMsg` recipient field submitted through the public `safe_verify_deposit` entry point on the satoshi-bridge.

---

### Recommendation

Move the registration check **before** `internal_deposit`. If the recipient is not registered, panic immediately so the entire transaction reverts atomically:

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
    // Check BEFORE minting so total_supply is never inflated on failure
    require!(
        self.token.accounts.get(&account_id).is_some(),
        "safe_mint: recipient account not registered"
    );
    self.token.internal_deposit(&self.bridge_id, amount.into());
    // ... transfer logic
}
```

This ensures `total_supply` is only increased when the full mint-and-transfer sequence can complete, preserving the 1:1 backing invariant between locked BTC and circulating nBTC.

---

### Proof of Concept

1. Alice locks 0.001 BTC on Bitcoin, embedding her NEAR account `alice.near` in the `DepositMsg`.
2. Alice has **not** called `storage_deposit` on the nbtc contract; `alice.near` is unregistered.
3. A relayer calls `safe_verify_deposit` on the satoshi-bridge with a valid Merkle proof.
4. The satoshi-bridge calls `nbtc.safe_mint(alice.near, 100_000, None)`.
5. `safe_mint` executes `internal_deposit(&bridge_id, 100_000)` → `total_supply += 100_000`, bridge balance `+= 100_000`.
6. `self.token.accounts.get(&alice.near)` returns `None` → function returns `U128(0)`.
7. No panic → `is_promise_success()` is `true` in the satoshi-bridge callback → deposit finalised, UTXO recorded.
8. **Result**: `total_supply` is 100,000 satoshis higher than the sum of all user balances; Alice's BTC is permanently locked; the 100,000 nBTC sit in the bridge's balance, available to be silently absorbed into protocol-fee accounting. [1](#0-0) [4](#0-3)

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

**File:** contracts/satoshi-bridge/src/nbtc/mint.rs (L46-54)
```rust
    pub fn mint_callback(
        &mut self,
        recipient_id: AccountId,
        mint_amount: U128,
        protocol_fee: U128,
        relayer_fee: U128,
        pending_utxo_info: PendingUTXOInfo,
    ) -> bool {
        let is_success = is_promise_success();
```
