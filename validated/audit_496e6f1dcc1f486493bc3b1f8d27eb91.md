### Title
Pause Bypass via `finish_withdraw_v2` Allows Outbound Transfers During Emergency Pause — (File: `near/omni-bridge/src/lib.rs`)

### Summary

The `finish_withdraw_v2` function in the NEAR `omni-bridge` contract lacks a pause check, while the primary outbound-transfer entry point `ft_on_transfer` is protected by `#[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]`. Any deployed bridge token can call `finish_withdraw_v2` directly, bypassing the pause and initiating outbound transfers even during an emergency stop.

### Finding Description

The NEAR bridge contract uses the `near-plugins` `Pausable` macro to gate its public entry points. Every user-facing function that moves funds or initiates cross-chain messages carries a `#[pause]` attribute:

- `ft_on_transfer` (handles `InitTransfer`, `FastFinTransfer`, `UtxoFinTransfer`) — `#[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]`
- `sign_transfer` — `#[pause(except(roles(Role::DAO)))]`
- `fin_transfer` — `#[pause(except(roles(Role::DAO)))]`
- `claim_fee` — `#[pause(except(roles(Role::DAO)))]`
- `deploy_token` — `#[pause(except(roles(Role::DAO)))]`
- `bind_token` — `#[pause(except(roles(Role::DAO)))]`
- `update_transfer_fee` — `#[pause]`

`finish_withdraw_v2`, however, carries **no pause attribute at all**: [1](#0-0) 

The function's only access control is a check that the caller (`env::predecessor_account_id()`) is a registered deployed bridge token: [2](#0-1) 

It then unconditionally increments the origin nonce, constructs a `TransferMessage`, stores it, and emits an `InitTransferEvent` — the same observable effect as a successful `ft_on_transfer → InitTransfer` call: [3](#0-2) 

### Impact Explanation

When the `PauseManager` or `DAO` pauses the bridge (e.g., in response to a discovered exploit on the EVM or Solana side), `ft_on_transfer` is blocked for all non-DAO callers. However, any deployed bridge token can still call `finish_withdraw_v2` on behalf of a user. The bridge token typically burns the user's NEP-141 tokens before making this call. The result is:

1. User tokens are burned on NEAR.
2. A pending `TransferMessage` is created in the bridge's storage.
3. `sign_transfer` is paused, so the MPC relayer cannot produce a signature to release funds on the destination chain.
4. The user's tokens are permanently locked (burned) with no corresponding release on the destination chain until the bridge is unpaused — and if the bridge is paused precisely because the destination chain is compromised, the release may never happen.

This is a **pause bypass** enabling unauthorized initiation of cross-chain transfers and potential permanent freezing of bridged funds, matching the allowed critical impact scope.

### Likelihood Explanation

`finish_withdraw_v2` is a public, non-`#[private]` function explicitly designed to be called by deployed bridge tokens as their outbound-transfer callback. Any user holding a deployed bridge token who calls the token's withdrawal interface triggers this path. No special role or privilege is required beyond holding the token. The attacker-controlled entry path is fully reachable by an unprivileged bridge user.

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

This ensures that when the bridge is paused, all outbound-transfer initiation paths — both the standard `ft_on_transfer` route and the bridge-token-callback route — are uniformly blocked.

### Proof of Concept

1. Admin calls `pause_all` (or sets the pause flag via `PauseManager`). `ft_on_transfer` is now blocked for non-DAO callers.
2. User calls `withdraw(amount, eth_recipient)` on a deployed bridge token (e.g., an `omni-token` instance).
3. The bridge token burns `amount` of the user's NEP-141 tokens.
4. The bridge token calls `bridge.finish_withdraw_v2(user, amount, eth_recipient)`.
5. `finish_withdraw_v2` executes without any pause check, increments `current_origin_nonce`, stores a `TransferMessage`, and emits `InitTransferEvent`.
6. The relayer attempts `sign_transfer` but is blocked by the pause.
7. The user's tokens are burned; no release occurs on Ethereum. Funds are frozen. [4](#0-3) [5](#0-4) [1](#0-0)

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
