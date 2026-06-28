### Title
`migrate_deployed_token` Removes `token_id_to_address` Binding, Permanently Locking Funds in Pending Transfers — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

`migrate_deployed_token` removes the old token's entry from `token_id_to_address` without processing or cancelling existing pending transfers. Any `init_transfer` message already stored in `pending_transfers` that references the old token ID can never be signed, permanently locking the user's bridged funds with no recovery path.

---

### Finding Description

`migrate_deployed_token` (DAO-only) performs the following key state mutations: [1](#0-0) 

It removes `token_id_to_address[(origin_chain, old_token)]` and replaces it with `token_id_to_address[(origin_chain, new_token)]`. It also updates `token_address_to_id[origin_address]` to point to `new_token`.

However, pending transfers stored in `pending_transfers` still carry `token: OmniAddress::Near(old_token)` — the field is set at `init_transfer` time and never updated. [2](#0-1) 

When a relayer later calls `sign_transfer` for such a pending transfer, the following sequence executes: [3](#0-2) 

1. `get_token_id(&OmniAddress::Near(old_token))` returns `old_token` directly (Near variant short-circuits the map lookup).
2. `get_token_address(destination_chain, old_token)` queries `token_id_to_address[(destination_chain, old_token)]` — **this entry was deleted by `migrate_deployed_token`** — and returns `None`.
3. The `unwrap_or_else` branch calls `env::panic_str(BridgeError::FailedToGetTokenAddress)`. [4](#0-3) 

There is no `cancel_transfer` or refund path in the contract. For deployed (mintable) tokens, `burn_tokens_if_needed` already burned the user's tokens during `init_transfer_internal`: [5](#0-4) 

The burned tokens cannot be recovered: `sign_transfer` panics, and no alternative processing path exists.

---

### Impact Explanation

**Critical — permanent loss of bridged funds.** Any user who called `init_transfer` with `old_token` before the migration has their tokens burned (deployed token) or locked (non-deployed token) with no mechanism to recover them. The `pending_transfers` entry remains indefinitely but can never be processed.

---

### Likelihood Explanation

Token migration is an explicitly supported, expected operational procedure — `migrate_deployed_token` exists precisely for upgrading token contracts. The DAO may legitimately invoke it without auditing the `pending_transfers` map for in-flight transfers referencing the old token. Any user whose transfer is in-flight during the migration window is permanently affected. [6](#0-5) 

---

### Recommendation

Before removing `token_id_to_address[(origin_chain, old_token)]`, verify that no pending transfers reference `old_token`. Options:

1. **Require zero pending transfers** for `old_token` before migration proceeds (analogous to the original report's `balanceOf(address(this)) == 0` check).
2. **Iterate and rewrite** all pending transfers referencing `OmniAddress::Near(old_token)` to `OmniAddress::Near(new_token)` atomically within `migrate_deployed_token`.
3. **Add a cancel/refund path** so users can reclaim locked or receive newly minted replacement tokens for stuck transfers.

---

### Proof of Concept

1. User calls `ft_transfer_call(bridge, 1000, msg=InitTransferMsg{recipient: eth_eoa, ...})` on `old_token`.
2. Bridge receives tokens; `burn_tokens_if_needed(old_token, 1000)` burns them (deployed token); `pending_transfers[transfer_id]` is stored with `token = OmniAddress::Near(old_token)`.
3. DAO calls `migrate_deployed_token(ChainKind::Eth, old_token, new_token)` — deletes `token_id_to_address[(Eth, old_token)]`.
4. Relayer calls `sign_transfer(transfer_id, ...)` — `get_token_address(Eth, old_token)` returns `None` → `env::panic_str(FailedToGetTokenAddress)`.
5. User's 1000 tokens are permanently lost: burned in step 2, unrecoverable in step 4. No cancel function exists. [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L462-470)
```rust
        let token_address = self
            .get_token_address(
                transfer_message.get_destination_chain(),
                self.get_token_id(&transfer_message.token),
            )
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });

```

**File:** near/omni-bridge/src/lib.rs (L540-553)
```rust
        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount,
            recipient: init_transfer_msg.recipient,
            fee: Fee {
                fee: init_transfer_msg.fee,
                native_fee: init_transfer_msg.native_token_fee,
            },
            sender: OmniAddress::Near(sender_id),
            msg: init_transfer_msg.msg.map(String::from).unwrap_or_default(),
            destination_nonce,
            origin_transfer_id: None,
        };
```

**File:** near/omni-bridge/src/lib.rs (L1368-1376)
```rust
    pub fn get_token_id(&self, address: &OmniAddress) -> AccountId {
        if let OmniAddress::Near(token_account_id) = address {
            token_account_id.clone()
        } else {
            self.token_address_to_id
                .get(address)
                .near_expect(BridgeError::TokenNotRegistered)
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L1604-1616)
```rust
    #[access_control_any(roles(Role::DAO))]
    #[payable]
    pub fn migrate_deployed_token(
        &mut self,
        origin_chain: ChainKind,
        old_token: AccountId,
        new_token: AccountId,
    ) {
        require!(
            env::attached_deposit() >= NEP141_DEPOSIT,
            BridgeError::NotEnoughAttachedDeposit.as_ref()
        );

```

**File:** near/omni-bridge/src/lib.rs (L1628-1642)
```rust
        let origin_address = self
            .token_id_to_address
            .remove(&(origin_chain, old_token.clone()))
            .near_expect(BridgeError::FailedToGetTokenAddress);

        require!(
            self.token_id_to_address
                .insert(&(origin_chain, new_token.clone()), &origin_address)
                .is_none(),
            BridgeError::TokenExists.as_ref()
        );

        self.token_address_to_id
            .insert(&origin_address, &new_token)
            .near_expect(BridgeError::ExpectedToOverwriteTokenAddress);
```

**File:** near/omni-bridge/src/lib.rs (L1806-1813)
```rust
    fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
        if self.is_deployed_token(&token) {
            ext_token::ext(token)
                .with_static_gas(BURN_TOKEN_GAS)
                .burn(amount)
                .detach();
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L1850-1857)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
```
