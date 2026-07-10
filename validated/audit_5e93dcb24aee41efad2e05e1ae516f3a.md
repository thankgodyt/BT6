### Title
`safe_mint` Passes Bridge Contract as `sender_id` in `ft_on_transfer` Callback, Misattributing User Identity to Receiver — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

When `safe_mint` is invoked with a non-`None` `msg` parameter, it internally calls `self.ft_transfer_call(account_id, amount, None, msg)`. Because this is an in-process Rust call (not a cross-contract call), `env::predecessor_account_id()` inside `ft_transfer_call` resolves to the **bridge contract** — the caller of `safe_mint` — not the actual depositing user. The NEP-141 standard propagates `predecessor_account_id()` as the `sender_id` argument to the receiver's `ft_on_transfer` callback. Any receiver contract that relies on `sender_id` to identify the depositing user will therefore see the bridge's account ID instead of the real user, causing fund misattribution or stuck/unrecoverable state.

---

### Finding Description

`safe_mint` in `contracts/nbtc/src/lib.rs` (lines 101–124) is the entry point for the safe-deposit flow (Omni Bridge integration). Its execution path when `msg` is `Some` is:

```
bridge::verify_deposit_v2 (safe path)
  → nbtc::safe_mint(account_id, amount, Some(msg))
      → self.ft_transfer_call(account_id, amount, None, msg)   // internal Rust call
          → env::predecessor_account_id()  ==  bridge_id       // NOT the user
          → ft_on_transfer(sender_id = bridge_id, amount, msg) // called on receiver
```

The NEP-141 `ft_transfer_call` implementation (provided by `near_contract_standards`) unconditionally uses `env::predecessor_account_id()` as the `sender_id` forwarded to the receiver's `ft_on_transfer`. Because `safe_mint` is reached via a cross-contract call **from the bridge**, `predecessor_account_id()` inside the nBTC contract is the bridge's account ID. The actual depositing user's identity is never passed to the receiver.

The `handle_post_action` path (used by the standard `mint` function) avoids this problem by explicitly threading `sender_id` as a parameter through a `#[private]` self-call and then passing it directly to `ft_on_transfer`. `safe_mint` has no equivalent mechanism.

---

### Impact Explanation

Any receiver contract that uses `sender_id` from `ft_on_transfer` to:

1. **Route refunds on failure** — if the receiver rejects the transfer and the NEP-141 resolver returns tokens to `sender_id`, the tokens are credited back to the bridge's nBTC balance, not the user's. The user's deposited BTC has been consumed (the UTXO is marked verified), but the minted nBTC is now held by the bridge with no on-chain path back to the user. This constitutes permanent loss of user funds.

2. **Attribute the deposit for accounting** — the bridge is credited as the depositor instead of the user. In the Omni Bridge integration this means the cross-chain transfer is attributed to the bridge account on the destination chain, not the user.

3. **Perform authorization checks** — a receiver that gates `ft_on_transfer` to specific senders may reject the call entirely (because `sender_id = bridge_id` is unexpected), causing the transfer to be returned and the deposit to be stuck.

Impact classification: **Medium** (broken callback rollback / stuck bridge state requiring operator intervention) with potential escalation to **Critical** (permanent loss of user funds) when the receiver routes refunds to `sender_id`.

---

### Likelihood Explanation

The `safe_mint` with `msg` path is the live production path for the Omni Bridge / safe-deposit integration. Any user who deposits BTC with a `safe_deposit` message that includes a forwarding `msg` triggers this code. No special attacker capability is required — a normal user performing a safe deposit is sufficient to reach the vulnerable path.

---

### Recommendation

Mirror the pattern used by `handle_post_action`: accept the actual user's account ID as an explicit parameter in `safe_mint`, then perform the transfer and `ft_on_transfer` call manually (using `internal_transfer` + `ext_ft_receiver::ext(...).ft_on_transfer(actual_user_id, ...)`) so that the correct `sender_id` is forwarded to the receiver, independent of `predecessor_account_id()`.

Alternatively, add a `sender_id: AccountId` parameter to `safe_mint` and pass it through to a dedicated internal helper that constructs the cross-contract `ft_on_transfer` call with the correct sender, matching the `handle_post_action` design already present in the contract.

---

### Proof of Concept

1. User deposits BTC with `deposit_msg.safe_deposit = Some(SafeDeposit { receiver_id: omni_bridge, msg: "<forward_msg>" })`.
2. Relayer calls `verify_deposit_v2` on the bridge; the bridge verifies the BTC inclusion proof and calls `nbtc::safe_mint(user_account_id, amount, Some("<forward_msg>"))`.
3. Inside `safe_mint`, `self.token.internal_deposit(&self.bridge_id, amount)` credits the bridge's nBTC balance.
4. `self.ft_transfer_call(user_account_id, amount, None, "<forward_msg>")` is called as an in-process Rust call. `env::predecessor_account_id()` = `bridge_id`.
5. The NEP-141 implementation transfers tokens from `bridge_id` to `user_account_id` (Omni Bridge) and schedules `omni_bridge::ft_on_transfer(sender_id = bridge_id, amount, "<forward_msg>")`.
6. The Omni Bridge receives `sender_id = bridge_id`. If it uses `sender_id` to determine the refund recipient and the cross-chain transfer fails, it refunds `bridge_id` — not the user.
7. The user's BTC UTXO is permanently marked as verified (consumed); the minted nBTC is held by the bridge with no user-accessible recovery path.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** contracts/nbtc/src/lib.rs (L331-334)
```rust
impl Contract {
    fn assert_bridge(&self) {
        require!(self.bridge_id == env::predecessor_account_id(), "Not Allow");
    }
```

**File:** contracts/nbtc/src/lib.rs (L384-416)
```rust
    #[private]
    pub fn handle_post_action(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) {
        require!(
            env::prepaid_gas() > GAS_FOR_FT_TRANSFER_CALL,
            "More gas is required"
        );
        require!(
            receiver_id != self.bridge_id,
            "handle_post_action: receiver_id must not be the bridge"
        );
        let amount = amount.into();
        self.token
            .internal_transfer(&sender_id, &receiver_id, amount, memo);
        let receiver_gas = env::prepaid_gas()
            .checked_sub(GAS_FOR_FT_TRANSFER_CALL)
            .unwrap_or_else(|| env::panic_str("Prepaid gas overflow"));
        // Initiating receiver's call and the callback
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
