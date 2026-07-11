### Title
`safe_mint` Permanently Locks nBTC Tokens in Bridge Account When Recipient Is Unregistered — (`contracts/nbtc/src/lib.rs`)

### Summary

The `safe_mint` function in the nBTC contract mints tokens to the bridge account **before** checking whether the recipient is registered. If the recipient is not registered, the function silently returns `U128(0)` without transferring the tokens, leaving them permanently stuck in the bridge account with no recovery path. This is a direct analog to the external report's class: a missing function/mechanism to handle a token accounting edge case, causing stuck funds and supply inflation.

### Finding Description

In `contracts/nbtc/src/lib.rs`, `safe_mint` (lines 100–124) executes `internal_deposit` to the `bridge_id` account unconditionally on line 112, then checks whether the intended recipient is registered on line 114. If the recipient has no storage registration, the function returns `PromiseOrValue::Value(U128(0))` on line 115 — a **successful** return, not a panic — without ever transferring the minted tokens.

```rust
// line 112 — tokens minted to bridge_id unconditionally
self.token.internal_deposit(&self.bridge_id, amount.into());

// line 114-116 — silent early return; tokens remain in bridge_id
if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));
}
``` [1](#0-0) 

Because this is a cross-contract call from the satoshi-bridge to the nBTC contract, the `internal_deposit` state change in the nBTC contract is **not rolled back** even if the bridge's callback subsequently panics. NEAR's cross-contract call model only reverts the caller's state on callback failure; the callee's committed state changes persist.

The nBTC contract has no function to recover tokens stranded in `bridge_id` by this path. The bridge contract's `lost_found` mechanism (in `token_transfer.rs`) is only populated by `transfer_nbtc_callback` failures — it is never triggered by `safe_mint` returning zero. [2](#0-1) 

The `burn` function in the nBTC contract can withdraw from `bridge_id`, but it destroys the tokens rather than returning them to the depositor, worsening the backed-supply invariant. [3](#0-2) 

### Impact Explanation

Two outcomes are possible depending on whether the bridge callback panics on a zero return:

1. **Callback panics**: The bridge's own state changes (e.g., marking the UTXO verified) are rolled back, so the user's BTC may be recoverable via the refund flow. However, the nBTC tokens already minted to `bridge_id` are **not** rolled back — the circulating supply is inflated without any BTC backing, violating the 1:1 peg invariant.

2. **Callback does not panic**: The UTXO is marked verified, the user's BTC is permanently locked in the deposit address, and the nBTC tokens are stuck in the bridge account. The user loses their entire deposit with no recourse.

In both cases, nBTC tokens are orphaned in the bridge account with no on-chain recovery mechanism, constituting a stuck bridge state requiring operator intervention and a broken backed-supply invariant.

### Likelihood Explanation

The `safe_deposit` flow is explicitly designed for integrations such as Omni Bridge where the recipient may be a contract account that has not yet called `storage_deposit` on the nBTC contract. Any deposit where the recipient's storage is not pre-registered triggers this path. This is a realistic, user-reachable condition: a user or integration that deposits BTC before registering the recipient account in the nBTC token contract will silently lose their tokens.

### Recommendation

Reorder the registration check to occur **before** minting:

```rust
pub fn safe_mint(...) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, "...");

    // Check registration BEFORE minting to avoid stranded tokens
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));
    }

    self.token.internal_deposit(&self.bridge_id, amount.into());
    // ... proceed with transfer
}
```

Alternatively, add a `lost_found`-style recovery entry in the nBTC contract when the early-return path is taken, or require the bridge to always pre-register the recipient before calling `safe_mint`.

### Proof of Concept

1. User deposits BTC to an address derived from a `DepositMsg` with a `safe_deposit` field, where `recipient_id` has not called `storage_deposit` on the nBTC contract.
2. A relayer calls `verify_deposit` on the satoshi-bridge.
3. The bridge cross-contract-calls `safe_mint(recipient_id, amount, msg)` on the nBTC contract.
4. `safe_mint` executes `self.token.internal_deposit(&self.bridge_id, amount.into())` — tokens are minted to the bridge account in the nBTC contract's state.
5. `self.token.accounts.get(&recipient_id).is_none()` is `true` — the function returns `PromiseOrValue::Value(U128(0))`.
6. The nBTC contract's state change (step 4) is committed and **cannot be rolled back** by the bridge's callback.
7. The minted tokens remain in `bridge_id`'s nBTC balance indefinitely. No function in either contract recovers them to the depositor. [4](#0-3)

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

**File:** contracts/nbtc/src/lib.rs (L150-177)
```rust
    pub fn burn(
        &mut self,
        burn_account_id: AccountId,
        burn_amount: U128,
        relayer_account_id: AccountId,
        relayer_fee: U128,
    ) {
        self.assert_bridge();
        self.token
            .internal_withdraw(&self.bridge_id, burn_amount.into());
        if relayer_fee.0 > 0 {
            if self.token.accounts.get(&relayer_account_id).is_none() {
                self.token.internal_register_account(&relayer_account_id);
            }
            self.token.internal_transfer(
                &self.bridge_id,
                &relayer_account_id,
                relayer_fee.into(),
                None,
            );
        }
        near_contract_standards::fungible_token::events::FtBurn {
            owner_id: &burn_account_id,
            amount: burn_amount,
            memo: None,
        }
        .emit();
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
