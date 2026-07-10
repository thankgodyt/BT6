### Title
Tokens Minted to `bridge_id` Before Registration Check in `safe_mint` Causes Permanent User Fund Loss - (File: contracts/nbtc/src/lib.rs)

### Summary
The `safe_mint` function in the nBTC contract mints tokens to `bridge_id` **before** verifying that the recipient `account_id` is registered. If the account is unregistered, the function silently returns `U128(0)` while the minted tokens remain permanently credited to the bridge's own balance — never reaching the user. This is the direct analog of the Morpho "virtual supply shares stealing interest" class: a phantom accounting entry (`bridge_id`'s balance) accumulates real value that belongs to actual depositors.

### Finding Description
In `contracts/nbtc/src/lib.rs`, `safe_mint` executes `internal_deposit` on `bridge_id` unconditionally, then checks registration:

```rust
self.token.internal_deposit(&self.bridge_id, amount.into());  // tokens minted here

if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));  // early exit — tokens stay in bridge_id
}
``` [1](#0-0) 

`internal_deposit` increases both the total supply and `bridge_id`'s balance atomically. When the early-return branch fires, the total nBTC supply has grown by `amount`, but no user account holds those tokens — they sit in `bridge_id`'s balance indefinitely. The bridge contract has no `safe_mint` callback analogous to `transfer_nbtc_callback` (which handles failed `ft_transfer` via `lost_found`), so there is no recovery path. [2](#0-1) 

By contrast, the `mint` function (used for protocol-fee minting) calls `mint_inner`, which auto-registers any account before depositing, so it never leaves tokens stranded:

```rust
fn mint_inner(&mut self, account_id: &AccountId, amount: U128) {
    if self.token.accounts.get(account_id).is_none() {
        self.token.internal_register_account(account_id);
    }
    self.token.internal_deposit(account_id, amount.into());
``` [3](#0-2) 

`safe_mint` deliberately does **not** auto-register, yet still mints before the guard — the wrong order.

### Impact Explanation
A user who deposits BTC but has not pre-registered their NEAR account in the nBTC contract will:
1. Have their BTC locked in the bridge (the deposit UTXO is consumed).
2. Receive zero nBTC — `safe_mint` returns `U128(0)`.
3. Have no on-chain recovery path: no `lost_found` entry is created, no refund is triggered.

The minted tokens accumulate in `bridge_id`'s balance, inflating the bridge's apparent nBTC holdings without backing. This matches **Critical — significant loss of user funds** from the allowed impact scope.

### Likelihood Explanation
NEP-141 storage registration is a separate, explicit step that many users omit. Any deposit flow that routes through `safe_mint` (rather than `mint`) for a first-time depositor will silently trigger this path. The attacker surface is every unprivileged BTC depositor whose NEAR account has not called `storage_deposit` on the nBTC contract.

### Recommendation
Perform the registration check **before** minting, mirroring `mint_inner`:

```rust
pub fn safe_mint(...) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, "...");

    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));  // check FIRST, mint nothing
    }

    self.token.internal_deposit(&self.bridge_id, amount.into());
    // ... proceed with transfer
}
```

Alternatively, add a `safe_mint` callback in the bridge contract that detects a `0` return and records the amount in `lost_found` for the depositor, consistent with the existing `transfer_nbtc_callback` pattern. [4](#0-3) 

### Proof of Concept
1. Alice holds BTC and a NEAR account but has **not** called `storage_deposit` on the nBTC contract.
2. Alice sends BTC to the bridge deposit address.
3. A relayer calls `verify_deposit` / `safe_verify_deposit`; the bridge calls `nbtc.safe_mint(alice, amount, ...)`.
4. `safe_mint` executes `internal_deposit(&bridge_id, amount)` — total supply increases by `amount`, `bridge_id` balance increases by `amount`.
5. `self.token.accounts.get(&alice)` returns `None` → function returns `U128(0)`.
6. Alice receives 0 nBTC. Her BTC UTXO is marked verified and cannot be refunded via `request_refund` (blocked by `verified_deposit_utxo` check).
7. `bridge_id`'s nBTC balance permanently holds Alice's `amount`, analogous to virtual shares holding interest that belongs to real suppliers. [5](#0-4) [6](#0-5)

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

**File:** contracts/nbtc/src/lib.rs (L341-346)
```rust
    fn mint_inner(&mut self, account_id: &AccountId, amount: U128) {
        if self.token.accounts.get(account_id).is_none() {
            self.token.internal_register_account(account_id);
        }
        self.token.internal_deposit(account_id, amount.into());
        near_contract_standards::fungible_token::events::FtMint {
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

**File:** contracts/satoshi-bridge/src/lib.rs (L140-146)
```rust
    pub lost_found: IterableMap<AccountId, u128>,
    pub acc_collected_protocol_fee: u128,
    pub cur_available_protocol_fee: u128,
    pub acc_claimed_protocol_fee: u128,
    pub cur_reserved_protocol_fee: u128,
    pub acc_protocol_fee_for_gas: u128,
    pub refund_requests: IterableMap<String, VRefundRequest>,
```

**File:** contracts/satoshi-bridge/src/refund.rs (L253-258)
```rust
        // after a consensus branch change.
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );
```
