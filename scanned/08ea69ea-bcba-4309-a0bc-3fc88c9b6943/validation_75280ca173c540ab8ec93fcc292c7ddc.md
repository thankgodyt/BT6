### Title
`finish_withdraw_v2` Lacks Pause Guard, Allowing Transfer Initiation While Bridge Is Paused — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

The NEAR bridge contract protects its primary transfer-initiation path (`ft_on_transfer`) with a `#[pause]` macro guard, but the legacy `finish_withdraw_v2` function — which also initiates bridge transfers — carries no pause check. Any user holding deployed bridge tokens can trigger `finish_withdraw_v2` through a deployed token contract's withdrawal flow while the bridge is paused, burning their NEAR-side tokens and creating a pending transfer with no cancellation path.

---

### Finding Description

The NEAR bridge contract derives from `near-plugins`' `Pausable` trait and applies `#[pause(except(roles(...)))]` to every externally-reachable transfer function:

- `ft_on_transfer` — `#[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]`
- `sign_transfer` — `#[pause(except(roles(Role::DAO)))]`
- `fin_transfer` — `#[pause(except(roles(Role::DAO)))]`
- `claim_fee` — `#[pause(except(roles(Role::DAO)))]`
- `deploy_token` — `#[pause(except(roles(Role::DAO)))]`
- `bind_token` — `#[pause(except(roles(Role::DAO)))]` [1](#0-0) [2](#0-1) [3](#0-2) 

However, `finish_withdraw_v2` — a public function that also creates a pending `TransferMessage` and emits an `InitTransferEvent` — has **no pause guard**:

```rust
pub fn finish_withdraw_v2(
    &mut self,
    #[serializer(borsh)] sender_id: &AccountId,
    #[serializer(borsh)] amount: u128,
    #[serializer(borsh)] recipient: String,
) {
    let token_id = env::predecessor_account_id();
    require!(self.is_deployed_token(&token_id),);

    self.current_origin_nonce += 1;
    let destination_nonce = self.get_next_destination_nonce(ChainKind::Eth);

    let transfer_message = TransferMessage { ... };

    let required_storage_balance =
        self.add_transfer_message(transfer_message.clone(), sender_id.clone());
    ...
    env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
}
``` [4](#0-3) 

The only access control is `require!(self.is_deployed_token(&token_id))`, which restricts the **caller** to a deployed bridge token contract — not to a privileged role. Any user who holds deployed bridge tokens can invoke the token contract's withdrawal function, which in turn calls `finish_withdraw_v2` on the bridge. The bridge then burns/locks the tokens on NEAR and records a pending transfer, all without checking the pause state.

---

### Impact Explanation

When the bridge is paused (e.g., due to a security incident on the EVM side):

1. A user calls `withdraw` on a deployed bridge token contract.
2. The token contract burns the user's NEAR-side tokens and calls `finish_withdraw_v2` on the bridge.
3. The bridge — with no pause check — increments the nonce, creates a `TransferMessage`, and emits `InitTransferEvent`.
4. The user's tokens are now **permanently burned on NEAR**.
5. `sign_transfer` is paused, so the transfer cannot be completed.
6. There is no `cancel_transfer` function; the pending transfer cannot be unwound.

If the bridge remains paused indefinitely (e.g., due to a critical exploit on the destination chain), the user's tokens are **permanently frozen** — burned on NEAR and undeliverable on EVM. This constitutes unauthorized permanent freezing of bridged funds, matching the critical impact scope. [5](#0-4) 

---

### Likelihood Explanation

- The attack path requires no special privileges: any holder of a deployed bridge token can trigger it.
- The entry point is a standard user-facing withdrawal on a deployed token contract, a routine bridge operation.
- The condition (bridge paused) is an expected operational state, not a rare edge case.
- No admin compromise, key leakage, or validator collusion is required.

---

### Recommendation

Add the same pause guard used on `ft_on_transfer` to `finish_withdraw_v2`:

```rust
#[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]
pub fn finish_withdraw_v2(
    &mut self,
    #[serializer(borsh)] sender_id: &AccountId,
    #[serializer(borsh)] amount: u128,
    #[serializer(borsh)] recipient: String,
) { ... }
```

This ensures that when the bridge is paused, no new transfer messages can be created through any code path, including the legacy withdrawal route.

---

### Proof of Concept

1. `PauseManager` pauses the bridge (e.g., due to a suspected exploit on Ethereum).
2. Alice holds 1000 `eth.bridge.near` tokens (a deployed bridge token).
3. Alice calls `withdraw(amount=1000, recipient="0xAlice")` on `eth.bridge.near`.
4. The token contract burns Alice's 1000 tokens and cross-contract-calls `bridge.finish_withdraw_v2(sender_id=Alice, amount=1000, recipient="0xAlice")`.
5. The bridge has no pause check; it increments `current_origin_nonce`, creates a `TransferMessage`, and emits `InitTransferEvent`. Alice's tokens are now burned.
6. Alice attempts to call `sign_transfer` to complete the transfer — it reverts because `sign_transfer` is paused.
7. There is no `cancel_transfer` or refund mechanism. Alice's 1000 tokens are permanently lost as long as the bridge remains paused. [6](#0-5) [2](#0-1)

### Citations

**File:** near/omni-bridge/src/lib.rs (L252-253)
```rust
    #[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) {
```

**File:** near/omni-bridge/src/lib.rs (L446-447)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_transfer(
```

**File:** near/omni-bridge/src/lib.rs (L672-673)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn fin_transfer(&mut self, #[serializer(borsh)] args: FinTransferArgs) -> Promise {
```

**File:** near/omni-bridge/src/lib.rs (L1314-1354)
```rust
    #[allow(clippy::needless_pass_by_value)]
    pub fn finish_withdraw_v2(
        &mut self,
        #[serializer(borsh)] sender_id: &AccountId,
        #[serializer(borsh)] amount: u128,
        #[serializer(borsh)] recipient: String,
    ) {
        let token_id = env::predecessor_account_id();
        require!(self.is_deployed_token(&token_id),);

        self.current_origin_nonce += 1;
        let destination_nonce = self.get_next_destination_nonce(ChainKind::Eth);

        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount: U128(amount),
            recipient: OmniAddress::Eth(
                H160::from_str(&recipient).near_expect(BridgeError::InvalidRecipientAddress),
            ),
            fee: Fee {
                fee: U128(0),
                native_fee: U128(0),
            },
            sender: OmniAddress::Near(sender_id.clone()),
            msg: String::new(),
            destination_nonce,
            origin_transfer_id: None,
        };

        let required_storage_balance =
            self.add_transfer_message(transfer_message.clone(), sender_id.clone());

        self.update_storage_balance(
            env::current_account_id(),
            required_storage_balance,
            NearToken::from_yoctonear(0),
        );

        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
    }
```
