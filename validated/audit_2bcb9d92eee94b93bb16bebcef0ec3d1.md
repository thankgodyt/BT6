### Title
`safe_mint` Mints nBTC to Bridge Before Checking Account Registration, Stranding Tokens When Recipient Is Unregistered - (File: contracts/nbtc/src/lib.rs)

### Summary
The `safe_mint` function in the nbtc token contract unconditionally mints tokens to the bridge's own account **before** checking whether the recipient account is registered. If the recipient is not registered, the function returns `U128(0)` and exits — leaving the minted tokens permanently stranded in the bridge's nbtc balance with no recovery path tracked anywhere in the contract.

### Finding Description
In `contracts/nbtc/src/lib.rs`, `safe_mint` performs `self.token.internal_deposit(&self.bridge_id, amount.into())` to credit the bridge contract itself, then checks registration:

```rust
self.token.internal_deposit(&self.bridge_id, amount.into());

if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));
}
``` [1](#0-0) 

When the account is absent the function returns `U128(0)` without:
- Transferring the minted tokens to the user
- Adding the amount to any `lost_found` entry for later recovery
- Burning the minted tokens to preserve supply integrity

The minted tokens remain in the bridge's nbtc balance, inflating it without a corresponding user balance and without any on-chain record of the debt. This is the direct analog of the external report's pattern: a state condition (disabled receiver / unregistered account) causes already-allocated tokens to be silently redirected away from the eligible recipient, with no mechanism to reclaim them.

The `lost_found` recovery map exists in the bridge's `ContractData` and is populated by `transfer_nbtc_callback` on failed transfers, but `safe_mint`'s early-return path bypasses that mechanism entirely. [2](#0-1) [3](#0-2) 

### Impact Explanation
A user who deposits BTC but whose NEAR account is not registered in the nbtc token contract will have their deposit processed — UTXO verified, nBTC minted to the bridge — but receive zero nBTC. The minted tokens are stranded in the bridge's nbtc balance with no on-chain tracking of the owed amount. If the bridge's deposit callback marks the UTXO as verified (the standard deposit flow), the user is also blocked from requesting a refund:

```rust
require!(
    !self.data().verified_deposit_utxo.contains(&utxo_storage_key)
        || refund_request.executed,
    "UTXO already verified via deposit, cannot refund"
);
``` [4](#0-3) 

This results in permanent loss of the user's deposited BTC and a broken 1:1 BTC:nBTC backing invariant, as the bridge holds excess nBTC supply with no corresponding user claim.

### Likelihood Explanation
NEP-141 tokens require explicit storage registration via `storage_deposit`. A user who deposits BTC without first registering their NEAR account in the nbtc contract — a realistic scenario for new users unfamiliar with NEAR's storage model, or users whose registration lapsed after `storage_unregister` — will trigger this path. The entry point is fully unprivileged: any BTC depositor can reach it. [5](#0-4) 

### Recommendation
Move the account-registration check **before** the mint. If the account is not registered, either reject the call (forcing the caller to register first) or, if silent handling is required, burn the minted tokens or record the owed amount in `lost_found` so the debt is tracked and recoverable.

### Proof of Concept
1. Alice deposits BTC to the bridge-derived address without calling `storage_deposit` on the nbtc contract.
2. The bridge verifies the deposit via the Light Client and calls `safe_mint(alice.near, amount, None)` on the nbtc contract.
3. `safe_mint` executes `self.token.internal_deposit(&self.bridge_id, amount.into())` — minting `amount` nBTC to the bridge.
4. `self.token.accounts.get(&alice.near)` returns `None`.
5. `safe_mint` returns `PromiseOrValue::Value(U128(0))`.
6. Alice receives 0 nBTC. The `amount` nBTC sits permanently in the bridge's balance with no `lost_found` entry and no recovery path.
7. The bridge marks Alice's deposit UTXO as verified, blocking any subsequent refund request. [6](#0-5) [7](#0-6)

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

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L54-74)
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
        event.emit();
        promise_success
```

**File:** contracts/satoshi-bridge/src/lib.rs (L140-140)
```rust
    pub lost_found: IterableMap<AccountId, u128>,
```

**File:** contracts/satoshi-bridge/src/refund.rs (L254-258)
```rust
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L377-381)
```rust
        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());

```
