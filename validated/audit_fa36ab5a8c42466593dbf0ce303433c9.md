### Title
Unregistered-Recipient `safe_mint` Permanently Traps nBTC in Bridge Contract - (File: `contracts/nbtc/src/lib.rs`)

### Summary
`safe_mint` in the nBTC token contract always mints tokens to `self.bridge_id` first, then silently returns early — without transferring to the user — when the recipient account is not registered. The minted nBTC is permanently stuck in the bridge contract's own token balance with no automatic recovery path.

### Finding Description
`safe_mint` (lines 101–124 of `contracts/nbtc/src/lib.rs`) follows this sequence:

1. **Always** calls `self.token.internal_deposit(&self.bridge_id, amount.into())` — minting the full amount into the bridge contract's own nBTC balance.
2. Checks whether `account_id` is registered: `if self.token.accounts.get(&account_id).is_none()`.
3. If the account is **not** registered, returns `PromiseOrValue::Value(U128(0))` immediately — the tokens are never forwarded to the user.

```rust
// contracts/nbtc/src/lib.rs  L101-L124
pub fn safe_mint(...) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, ...);
    self.token.internal_deposit(&self.bridge_id, amount.into()); // ← always minted to bridge

    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));  // ← early return, tokens stuck
    }
    // transfer to user only if registered
    ...
}
```

The nBTC contract has no recovery function for tokens held in `bridge_id`'s balance that were not tracked by the satoshi-bridge's protocol-fee accounting (`cur_available_protocol_fee`). The satoshi-bridge's `internal_withdraw_protocol_fee` only releases amounts that were explicitly credited to `cur_available_protocol_fee`; tokens silently deposited via the `safe_mint` early-return path are invisible to that accounting and cannot be reclaimed through any public or privileged call. [1](#0-0) [2](#0-1) 

### Impact Explanation
Every BTC deposit whose recipient NEAR account is not registered in the nBTC token contract results in:
- The user's BTC being locked on the Bitcoin side (irreversible once the deposit UTXO is consumed by the bridge).
- The corresponding nBTC being minted into the bridge contract's own balance with no record in `cur_available_protocol_fee`.
- The user receiving zero nBTC and having no on-chain mechanism to claim or recover the funds.

This is permanent, irrecoverable loss of user funds — matching the **Critical** impact class: *"Significant loss, theft, destruction, or permanent locking of user or protocol funds."* [3](#0-2) [4](#0-3) 

### Likelihood Explanation
NEAR accounts must explicitly register storage with a token contract before they can hold a balance. A user who generates a deposit address but has not yet called `storage_deposit` on the nBTC contract — a common onboarding scenario — will trigger this path. No special attacker capability is required; any ordinary depositor whose account is unregistered at the time the bridge processes the deposit will lose funds. [5](#0-4) 

### Recommendation
Do not mint to `self.bridge_id` before confirming the recipient is registered. Two safe alternatives:

1. **Revert if unregistered**: `require!(self.token.accounts.get(&account_id).is_some(), "Recipient not registered")` before any minting, so the bridge can handle the failure and route to a lost-and-found or refund path.
2. **Mint directly to the recipient**: Use `mint_inner(&account_id, amount)` only after confirming registration, eliminating the intermediate bridge-balance step entirely.

Additionally, the satoshi-bridge should track any tokens that land in the bridge's own nBTC balance outside of the protocol-fee accounting so they can be recovered. [1](#0-0) 

### Proof of Concept
1. Alice sends 0.01 BTC to her bridge deposit address.
2. A relayer submits the Merkle inclusion proof; the bridge verifies it and calls `safe_mint(alice.near, 1_000_000, None)` on the nBTC contract.
3. Alice has never called `storage_deposit` on the nBTC contract, so `self.token.accounts.get(&alice.near)` returns `None`.
4. `safe_mint` executes `internal_deposit(&self.bridge_id, 1_000_000)` — 1 000 000 satoshi-units of nBTC are credited to the bridge contract's own balance.
5. The function returns `U128(0)`. Alice receives nothing.
6. The bridge's `cur_available_protocol_fee` is unchanged; `internal_withdraw_protocol_fee` cannot release these tokens.
7. The only on-chain operation that touches `bridge_id`'s nBTC balance is `burn`, which would destroy the tokens rather than return them to Alice.
8. Alice's 0.01 BTC is permanently lost. [3](#0-2) [6](#0-5)

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

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L11-21)
```rust
    pub fn internal_withdraw_protocol_fee(&self, amount: u128) -> Promise {
        ext_ft_core::ext(self.internal_config().nbtc_account_id.clone())
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .with_static_gas(GAS_FOR_TOKEN_TRANSFER)
            .ft_transfer(env::predecessor_account_id(), amount.into(), None)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_AFTER_TOKEN_TRANSFER)
                    .withdraw_protocol_fee_callback(amount.into()),
            )
    }
```

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L39-51)
```rust
    pub fn withdraw_protocol_fee_callback(&mut self, amount: U128) -> bool {
        let promise_success = is_promise_success();
        let event = Event::WithdrawBridgeProtocolFee {
            amount,
            success: promise_success,
        };
        if !promise_success {
            self.data_mut().cur_available_protocol_fee += amount.0;
            self.data_mut().acc_claimed_protocol_fee -= amount.0;
        }
        event.emit();
        promise_success
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
