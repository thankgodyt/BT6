### Title
Broken Mint Rollback in `safe_mint` Leaves nBTC Permanently Stranded in Bridge Balance When Recipient Is Unregistered — (File: `contracts/nbtc/src/lib.rs`)

### Summary
`safe_mint` unconditionally mints nBTC to the bridge's own account before checking whether the intended recipient has a registered storage account. If the recipient is unregistered, the function returns `U128(0)` without burning the already-minted tokens, permanently inflating the circulating supply with tokens that are stranded in the bridge balance and unreachable by the user.

### Finding Description
In `safe_mint`, the very first state-mutating operation is `self.token.internal_deposit(&self.bridge_id, amount.into())`, which increases both the bridge's token balance and the global total supply by `amount`. Only after this irreversible state change does the function check whether `account_id` has a registered storage slot:

```rust
self.token.internal_deposit(&self.bridge_id, amount.into());   // supply inflated here

if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));                      // early exit, no burn
}
``` [1](#0-0) 

When the early-exit branch is taken, the minted tokens remain in `bridge_id`'s balance with no automatic burn, no `lost_found` entry, and no recovery path. The `lost_found` mechanism that exists in the satoshi-bridge (`transfer_nbtc_callback`) applies only to `internal_transfer_nbtc` failures, not to this code path. [2](#0-1) 

The `ft_transfer_call` / `ft_on_transfer` callback path (the NEP-141 analog of the ERC-777 callback) is only reached when the account IS registered. When it is reached with `msg = Some(...)`, the callback chain (`ft_on_transfer` → `ft_resolve_transfer`) is fully detached, meaning any refund of unused tokens flows back to `bridge_id` rather than being burned, again leaving the total supply permanently elevated relative to what was actually delivered to the user. [3](#0-2) [4](#0-3) 

### Impact Explanation
Every time a deposit is processed for an unregistered recipient account, the nBTC total supply grows by `amount` while the user receives zero tokens. The corresponding BTC is already locked in the bridge's Bitcoin UTXO set. The stranded nBTC tokens sit in the bridge's own balance with no on-chain mechanism to burn them or credit them to the user later. This constitutes a broken callback-rollback and a stuck bridge state that requires manual operator intervention to resolve, matching the **Medium** impact class: *"Harmful smart-contract behavior without direct funds theft, including permanent burning below backed supply, broken callback rollback, or stuck bridge state requiring operator intervention."*

### Likelihood Explanation
The trigger is realistic and requires no special privilege. A user who deposits BTC before registering their NEAR account for nBTC storage (a common ordering mistake, especially for new users or DeFi integrations) will cause the bridge to call `safe_mint` with an unregistered `account_id`. The `DepositMsg.recipient_id` field is entirely user-controlled, so any depositor can produce this condition, intentionally or accidentally. [5](#0-4) 

### Recommendation
Move `internal_deposit` to after the registration check, or burn the minted tokens before returning when the account is unregistered:

```rust
// Option A: guard before minting
if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));
}
self.token.internal_deposit(&self.bridge_id, amount.into());
```

Alternatively, add the stranded amount to the `lost_found` map (keyed by `account_id`) so the user can claim it after registering, consistent with how `transfer_nbtc_callback` handles failed transfers elsewhere in the system.

### Proof of Concept
1. Alice sends 0.01 BTC to the bridge's deposit address with an OP_RETURN payload encoding `DepositMsg { recipient_id: "alice.near", safe_deposit: Some(...) }`.
2. Alice's NEAR account `alice.near` has never called `storage_deposit` on the nBTC contract, so `token.accounts.get(&alice.near)` returns `None`.
3. A relayer submits the Merkle proof; the bridge verifies it and calls `nbtc.safe_mint(alice.near, 1_000_000, Some(msg))`.
4. `internal_deposit(&bridge_id, 1_000_000)` executes — total supply increases by 1,000,000 satoshis worth of nBTC, all credited to `bridge_id`.
5. The `is_none()` check fires; the function returns `U128(0)`.
6. Alice receives zero nBTC. Her BTC is locked. The 1,000,000 nBTC units are permanently stranded in the bridge's own balance with no on-chain recovery path. [6](#0-5)

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

**File:** contracts/nbtc/src/lib.rs (L408-416)
```rust
        ext_ft_receiver::ext(receiver_id.clone())
            .with_static_gas(receiver_gas)
            .ft_on_transfer(sender_id.clone(), amount.into(), msg)
            .then(
                ext_ft_resolver::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_RESOLVE_TRANSFER)
                    .ft_resolve_transfer(sender_id, receiver_id, amount.into()),
            )
            .detach();
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
