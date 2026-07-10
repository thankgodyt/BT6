### Title
`safe_mint` Mints Tokens to Bridge Before Checking Recipient Registration, Causing Unbacked Supply Inflation and Permanent User Fund Loss — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

The `safe_mint` function in the `nbtc` contract unconditionally mints tokens to `bridge_id` **before** checking whether the recipient account is registered. If the recipient is not registered, the function silently returns `U128(0)` without reverting or burning the already-minted tokens. This creates a supply/accounting inconsistency: total supply increases, `bridge_id` holds tokens with no corresponding user claim, and the depositing user receives nothing.

---

### Finding Description

In `contracts/nbtc/src/lib.rs`, `safe_mint` executes in this order:

1. Mints `amount` tokens directly into `bridge_id`'s balance via `internal_deposit`.
2. **Then** checks whether `account_id` has a registered storage account.
3. If `account_id` is **not** registered, returns `PromiseOrValue::Value(U128(0))` — without reverting, without burning the already-minted tokens.

```rust
// contracts/nbtc/src/lib.rs lines 101–124
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
    self.token.internal_deposit(&self.bridge_id, amount.into()); // ← tokens minted here

    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0)); // ← early return, tokens already minted
    }
    ...
}
``` [1](#0-0) 

The `internal_deposit` call at line 112 increases both `bridge_id`'s balance and the global `total_supply`. The early return at line 115 does not undo this state change. The minted tokens remain in `bridge_id` indefinitely, indistinguishable from legitimately held protocol-fee tokens. [2](#0-1) 

This is structurally identical to the external report's root cause: two code paths share a counter/state variable (`numMinted` / `total_supply`), but one path (`mintTokenId` / `safe_mint` early-return) leaves the shared state mutated without completing the intended operation, causing a permanent divergence between the accounting variable and the actual distribution of tokens.

---

### Impact Explanation

- **Total supply is inflated** without a corresponding user balance. Every unregistered-recipient `safe_mint` call permanently increases `ft_total_supply()` by `amount` while the user receives zero nBTC.
- **User funds are permanently lost.** The depositing user sent real BTC to the bridge's deposit address. The bridge's deposit flow marks the UTXO as verified (`verified_deposit_utxo`) after calling `safe_mint`, preventing re-submission of the same proof. The user cannot recover their BTC and receives no nBTC.
- **Stuck tokens in `bridge_id`.** The orphaned nBTC balance in `bridge_id` can be confused with legitimately accumulated protocol fees, potentially allowing the protocol to withdraw tokens it did not earn, or causing accounting errors in fee-tracking fields (`cur_available_protocol_fee`, `acc_collected_protocol_fee`). [3](#0-2) 

This matches the **Critical** impact class: significant loss and permanent locking of user funds, and unbacked supply inflation of the bridged token.

---

### Likelihood Explanation

Any user who deposits BTC to the bridge without first registering a storage account on the nbtc contract triggers this path. Storage registration is a separate, non-obvious prerequisite on NEAR (NEP-145). New or unsophisticated users, integrations, or smart-contract callers that omit the `storage_deposit` step before depositing will silently lose funds. No privileged access is required; the entry path is fully public.

---

### Recommendation

Reorder the operations in `safe_mint` so that the recipient's registration is checked **before** any tokens are minted:

```rust
pub fn safe_mint(...) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, "...");

    // Check registration FIRST, before minting anything
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));
    }

    self.token.internal_deposit(&self.bridge_id, amount.into());
    // ... proceed with transfer
}
```

Alternatively, if early-return semantics must be preserved for the caller's rollback logic, replace the early return with a `panic!`/`env::panic_str` so the entire NEAR transaction reverts and no state is mutated.

---

### Proof of Concept

1. User registers a deposit address derived from their `DepositMsg` on the bridge.
2. User sends 1 BTC to that address **without** calling `storage_deposit` on the nbtc contract.
3. Relayer submits `verify_deposit` with a valid Merkle proof. The bridge calls `safe_mint(user_account, 100_000_000, None)` on the nbtc contract.
4. Inside `safe_mint`: `internal_deposit(&bridge_id, 100_000_000)` executes — `bridge_id` balance +1 BTC, `total_supply` +1 BTC.
5. `self.token.accounts.get(&user_account).is_none()` → `true` → returns `U128(0)`.
6. The bridge marks the UTXO as verified (`verified_deposit_utxo.insert(...)`).
7. User's BTC is locked. User's nBTC balance: 0. `total_supply` is inflated by 1 BTC worth of nBTC with no user backing it. [2](#0-1) [4](#0-3)

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

**File:** contracts/satoshi-bridge/src/lib.rs (L141-146)
```rust
    pub acc_collected_protocol_fee: u128,
    pub cur_available_protocol_fee: u128,
    pub acc_claimed_protocol_fee: u128,
    pub cur_reserved_protocol_fee: u128,
    pub acc_protocol_fee_for_gas: u128,
    pub refund_requests: IterableMap<String, VRefundRequest>,
```

**File:** contracts/satoshi-bridge/src/refund.rs (L377-381)
```rust
        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());

```
