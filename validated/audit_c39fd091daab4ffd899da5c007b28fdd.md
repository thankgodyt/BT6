### Title
Silent Token Loss in `safe_mint` When Recipient Account Is Unregistered - (File: `contracts/nbtc/src/lib.rs`)

### Summary

The `safe_mint` function in the `nbtc` contract silently mints tokens to the bridge's own balance and returns `U128(0)` when the recipient `account_id` has no storage registration, without reverting or propagating an error. Because the bridge marks the deposit UTXO as verified regardless of this silent failure, the depositing user permanently loses their BTC with no recovery path.

### Finding Description

`safe_mint` is the bridge-callable entry point for crediting a user's nBTC after a verified BTC deposit. Its execution has two distinct phases:

**Phase 1 – unconditional mint to bridge:** [1](#0-0) 

```rust
self.token.internal_deposit(&self.bridge_id, amount.into());
```

Tokens are minted into the bridge contract's own nBTC balance before any check on the recipient.

**Phase 2 – silent early return if recipient is unregistered:** [2](#0-1) 

```rust
if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));
}
```

If the recipient has never called `storage_deposit` on the nBTC contract (a fresh NEAR account), the function returns `U128(0)` — a value indistinguishable from a zero-amount transfer — without reverting, without emitting an error event, and without placing the amount in the `lost_found` ledger.

The result is:

1. `amount` nBTC tokens now exist in the bridge's own balance on the nBTC contract.
2. The bridge's deposit callback receives `U128(0)` as the "used amount," which it cannot distinguish from a legitimate zero-transfer outcome.
3. The bridge marks the deposit UTXO in `verified_deposit_utxo`, permanently blocking any future `verify_deposit` or `request_refund` for the same UTXO. [3](#0-2) 

The minted tokens accumulate silently in the bridge's balance with no automatic crediting mechanism, and the user's BTC is permanently locked.

This is the direct analog of H-02: in that report, a fresh recipient address caused a silent failure in the consensus-layer hook while the application-layer transaction succeeded, leaving the registered contract permanently unable to earn fees. Here, a fresh (unregistered) NEAR recipient causes a silent failure inside `safe_mint` while the bridge-side deposit transaction succeeds, leaving the user permanently unable to recover their BTC.

### Impact Explanation

**Critical.** A user who deposits BTC specifying a NEAR `recipient_id` that has not yet registered storage on the nBTC contract will:

- Have their BTC deposit UTXO permanently consumed (marked verified, blocking re-deposit and refund).
- Never receive the corresponding nBTC tokens.
- Have no on-chain mechanism to recover the minted tokens, which sit in the bridge's own nBTC balance.

This constitutes a significant, permanent loss of user funds triggered by a publicly reachable code path.

### Likelihood Explanation

Any user who generates a deposit address for a freshly created NEAR account — before that account has called `storage_deposit` on the nBTC contract — will trigger this path. This is a realistic scenario: users routinely create a new NEAR account specifically to receive bridged assets, and the storage registration step is a separate, non-obvious prerequisite. The `DepositMsg` struct accepts any valid `AccountId` with no on-chain pre-validation of storage registration. [4](#0-3) 

### Recommendation

Remove the silent early-return branch. Instead, either:

1. **Auto-register the recipient** inside `safe_mint` (mirroring what `mint_inner` already does): [5](#0-4) 

   ```rust
   if self.token.accounts.get(&account_id).is_none() {
       self.token.internal_register_account(&account_id);
   }
   ```

2. **Panic/revert** if the account is unregistered, so the bridge-side callback can detect the failure and place the amount in `lost_found` or trigger a refund.

Option 1 is preferred because it eliminates the discrepancy entirely and matches the behavior of `mint_inner`.

### Proof of Concept

1. Alice creates a fresh NEAR account `alice.near` (no storage deposit on nBTC).
2. Alice generates a BTC deposit address embedding `recipient_id: "alice.near"` in the `DepositMsg`.
3. Alice sends BTC to that address.
4. A relayer calls `verify_deposit` on the bridge; the bridge verifies the Merkle proof and calls `safe_mint("alice.near", amount, None)` on the nBTC contract.
5. Inside `safe_mint`:
   - Line 112: `amount` nBTC is minted to `bridge_id`'s balance.
   - Line 114–116: `alice.near` has no storage registration → function returns `U128(0)`.
6. The bridge's deposit callback receives `U128(0)`, marks the UTXO in `verified_deposit_utxo`.
7. Alice's BTC is consumed; she holds 0 nBTC; the minted tokens sit in the bridge's balance with no recovery path. [6](#0-5)

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

**File:** contracts/satoshi-bridge/src/lib.rs (L132-132)
```rust
    pub verified_deposit_utxo: LookupSet<String>,
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L12-28)
```rust
pub struct DepositMsg {
    // The NEAR account receiving nBTC.
    pub recipient_id: AccountId,
    // Parameters for executing ft_transfer_call after successful nBTC minting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_actions: Option<Vec<PostAction>>,
    // Used to support other dApps extending based on verify_deposit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_msg: Option<String>,
    // Replacment for the legacy post_actions to support safer cross-contract calls.
    // If this field is present, the legacy post_actions field must be None
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_deposit: Option<SafeDepositMsg>,
    // BTC address for refund if deposit is never finalized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_address: Option<String>,
}
```
