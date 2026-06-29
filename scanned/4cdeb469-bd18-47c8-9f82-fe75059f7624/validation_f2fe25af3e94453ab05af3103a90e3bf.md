### Title
Minted Tokens Credited to Bridge Contract Instead of Intended Recipient When `msg` Is Non-Empty - (File: `near/omni-token/src/lib.rs`)

### Summary

In `OmniToken::mint()`, when the optional `msg` parameter is `Some`, newly minted tokens are deposited into the **bridge contract's** account (`env::predecessor_account_id()`) rather than the intended recipient's account (`account_id`). This is the direct analog of the reported bug: the user-supplied recipient parameter is silently replaced by the caller's address. Any partial refund from the downstream `ft_on_transfer` callback is then credited back to the bridge contract and permanently stranded there, causing irreversible loss of bridged funds.

### Finding Description

`OmniToken::mint()` accepts three parameters: `account_id` (the intended token recipient), `amount`, and an optional `msg`. When `msg` is `None`, the function correctly deposits tokens directly to `account_id`:

```rust
self.token.internal_deposit(&account_id, amount.into());
```

But when `msg` is `Some`, the deposit target is silently switched to the bridge contract:

```rust
self.token
    .internal_deposit(&env::predecessor_account_id(), amount.into()); // bridge contract, not account_id!

self.ft_transfer_call(account_id, amount, None, msg)
``` [1](#0-0) 

The bridge contract's `send_tokens()` function is the sole caller of `mint()` with a non-empty `msg`. It passes `recipient` as `account_id` and `Some(msg.to_string())` when the transfer carries a message:

```rust
ext_token::ext(token)
    .with_attached_deposit(deposit)
    .with_static_gas(MINT_TOKEN_GAS.saturating_add(ft_transfer_call_gas))
    .mint(
        recipient,
        amount,
        (!msg.is_empty()).then(|| msg.to_string()),
    )
``` [2](#0-1) 

Because `internal_deposit` credits the bridge contract, the bridge contract becomes the `sender_id` in the subsequent `ft_transfer_call`. NEP-141's `ft_resolve_transfer` refunds any unused amount to `sender_id` — the bridge contract — not to the intended recipient: [3](#0-2) 

The bridge contract's `fin_transfer_send_tokens_callback` then attempts to burn the **full** `amount_without_fee` if a refund is detected, but the bridge contract only holds the partial unused amount. This mismatch causes the burn to fail, leaving the partial refund permanently stranded in the bridge contract's token balance with no recovery path. [4](#0-3) 

### Impact Explanation

When a cross-chain inbound transfer carries a non-empty `msg` (e.g., a swap instruction targeting a NEAR DeFi contract), and the recipient contract's `ft_on_transfer` returns a non-zero unused amount (partial rejection), the refunded tokens accumulate in the bridge contract's NEP-141 balance. There is no function in the bridge contract to redistribute or recover these tokens. The bridged funds are permanently lost. This constitutes irreversible loss of user funds across the bridge.

### Likelihood Explanation

The `msg` field is a documented, user-controlled feature of the bridge protocol — it is the mechanism for composable cross-chain calls (e.g., "bridge and swap"). Any user who initiates a transfer with a non-empty `msg` to a NEAR contract that partially rejects the transfer (a normal NEP-141 behavior) will trigger this loss. This is a realistic, unprivileged, attacker-reachable path requiring no special role or key compromise.

### Recommendation

Replace `env::predecessor_account_id()` with `account_id` in the `internal_deposit` call inside the `Some(msg)` branch:

```rust
if let Some(msg) = msg {
    self.token
        .internal_deposit(&account_id, amount.into()); // fix: use account_id, not predecessor

    self.ft_transfer_call(account_id, amount, None, msg)
}
```

This ensures the minted tokens are always credited to the intended recipient, and any partial refund from `ft_on_transfer` is correctly returned to that recipient rather than to the bridge contract.

### Proof of Concept

1. Alice initiates a cross-chain transfer from Ethereum to NEAR with `msg = '{"action":"swap",...}'` targeting a NEAR DEX contract as recipient.
2. The bridge finalizes the transfer and calls `send_tokens(token, dex_contract, amount, msg)`.
3. `send_tokens` calls `ext_token::ext(token).mint(dex_contract, amount, Some(msg))`.
4. Inside `OmniToken::mint()`, `internal_deposit(&env::predecessor_account_id(), amount)` credits `amount` tokens to the **bridge contract**, not `dex_contract`.
5. `ft_transfer_call(dex_contract, amount, None, msg)` is called; the DEX's `ft_on_transfer` partially processes the swap and returns `unused = amount / 2`.
6. `ft_resolve_transfer` refunds `amount / 2` tokens to `sender_id = bridge_contract`.
7. `fin_transfer_send_tokens_callback` sees a partial result and attempts `burn_tokens_if_needed(token, amount_without_fee)` — but the bridge contract only holds `amount / 2`, so the burn panics or the tokens remain stranded.
8. Alice loses `amount / 2` bridged tokens permanently. [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** near/omni-token/src/lib.rs (L126-144)
```rust
    #[payable]
    fn mint(
        &mut self,
        account_id: AccountId,
        amount: U128,
        msg: Option<String>,
    ) -> PromiseOrValue<U128> {
        self.assert_controller();

        if let Some(msg) = msg {
            self.token
                .internal_deposit(&env::predecessor_account_id(), amount.into());

            self.ft_transfer_call(account_id, amount, None, msg)
        } else {
            self.token.internal_deposit(&account_id, amount.into());
            PromiseOrValue::Value(amount)
        }
    }
```

**File:** near/omni-token/src/lib.rs (L229-243)
```rust
#[near]
impl FungibleTokenResolver for OmniToken {
    #[private]
    fn ft_resolve_transfer(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
    ) -> U128 {
        let (used_amount, _burned_amount) =
            self.token
                .internal_ft_resolve_transfer(&sender_id, receiver_id, amount);

        used_amount.into()
    }
```

**File:** near/omni-bridge/src/lib.rs (L1692-1718)
```rust
    pub fn fin_transfer_send_tokens_callback(
        &mut self,
        #[serializer(borsh)] transfer_message: TransferMessage,
        #[serializer(borsh)] fee_recipient: &AccountId,
        #[serializer(borsh)] is_ft_transfer_call: bool,
        #[serializer(borsh)] storage_owner: &AccountId,
        #[serializer(borsh)] lock_actions: Vec<LockAction>,
    ) {
        let token = self.get_token_id(&transfer_message.token);

        if Self::is_refund_required(is_ft_transfer_call) {
            self.burn_tokens_if_needed(
                token.clone(),
                U128(
                    transfer_message
                        .amount_without_fee()
                        .near_expect(BridgeError::InvalidFee),
                ),
            );

            self.revert_lock_actions(&lock_actions);

            self.remove_fin_transfer(&transfer_message.get_transfer_id(), storage_owner);

            env::log_str(
                &OmniBridgeEvent::FailedFinTransferEvent { transfer_message }.to_log_string(),
            );
```

**File:** near/omni-bridge/src/lib.rs (L2082-2101)
```rust
        } else if is_deployed_token {
            let deposit = if msg.is_empty() {
                NO_DEPOSIT
            } else {
                ONE_YOCTO
            };

            require!(
                ft_transfer_call_gas >= MIN_FT_TRANSFER_CALL_GAS,
                BridgeError::NotEnoughGasForTokenTransfer(ft_transfer_call_gas).as_ref()
            );

            ext_token::ext(token)
                .with_attached_deposit(deposit)
                .with_static_gas(MINT_TOKEN_GAS.saturating_add(ft_transfer_call_gas))
                .mint(
                    recipient,
                    amount,
                    (!msg.is_empty()).then(|| msg.to_string()),
                )
```
