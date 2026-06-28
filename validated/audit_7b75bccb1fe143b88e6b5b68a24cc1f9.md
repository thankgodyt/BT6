### Title
Pause Bypass via `finish_withdraw_v2` Lacking `#[pause]` Guard - (File: `near/omni-bridge/src/lib.rs`)

### Summary

The NEAR omni-bridge contract exposes two code paths that both initiate a NEAR→ETH transfer and emit `InitTransferEvent`. The primary path, `ft_on_transfer`, is correctly guarded with `#[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]`. The secondary legacy path, `finish_withdraw_v2`, is a public function callable by any deployed bridge token and carries **no pause guard at all**. When the bridge is paused in an emergency, any user who holds a deployed bridge token that exposes a `withdraw`-style function can still lock/burn tokens and create pending transfer records, bypassing the intended emergency stop.

### Finding Description

`ft_on_transfer` is the standard NEP-141 callback entry point for initiating outbound transfers. It is decorated with `#[pause]`, so when the bridge operator pauses the contract, normal users are blocked from initiating new transfers through this path. [1](#0-0) 

`finish_withdraw_v2` is a separate public function that performs the **identical core action**: it increments the origin nonce, constructs a `TransferMessage`, inserts it into `pending_transfers`, and emits `OmniBridgeEvent::InitTransferEvent`. It is callable by any account that `is_deployed_token` returns `true` for (i.e., any token in `deployed_tokens` or `deployed_tokens_v2`). [2](#0-1) 

The function has **no** `#[pause]`, `#[trusted_relayer]`, or `#[access_control_any]` decorator: [3](#0-2) 

The only guard is:

```rust
require!(self.is_deployed_token(&token_id),);
```

which is satisfied by any token previously deployed through the bridge's `deploy_token` / `bind_token` flow. [4](#0-3) 

The old rainbow-bridge token contracts (whose account IDs are tracked in `deployed_tokens`) expose a `withdraw(amount, recipient)` entry point that cross-contract-calls `finish_withdraw_v2` on the locker. A user holding such a token can invoke this path at any time, regardless of the bridge's pause state.

### Impact Explanation

When the bridge is paused (e.g., due to a discovered vulnerability in the signing or proof pipeline), the operator's intent is to halt **all** new transfer initiations. `finish_withdraw_v2` defeats this intent:

1. The user's tokens are burned/locked inside the token contract before the cross-contract call is made.
2. A `TransferMessage` is inserted into `pending_transfers` and an `InitTransferEvent` is emitted on-chain.
3. Although `sign_transfer` is also paused and cannot immediately finalize the transfer, the event is now on-chain and visible to relayers. If the pause is lifted even briefly, or if the vulnerability being mitigated is in a different subsystem, the pending transfer can be picked up and signed.
4. The nonce counter is permanently incremented, which can cause ordering or accounting issues.

This is a **pause bypass** — an explicitly listed Critical impact class: *"pause bypass … that lets an attacker execute bridge … actions."* [5](#0-4) 

### Likelihood Explanation

- The deployed bridge tokens from the legacy rainbow bridge (accounts matching `factory.bridge.near`, `eth-connector.near`, etc.) are already registered in `deployed_tokens`.
- Any holder of such a token can call its `withdraw` function, which cross-contract-calls `finish_withdraw_v2`.
- No special role, stake, or privileged access is required beyond holding a deployed bridge token.
- The attacker does not need to know the bridge is paused in advance; they simply attempt the withdrawal and it succeeds.

### Recommendation

Add the `#[pause]` attribute to `finish_withdraw_v2`, consistent with `ft_on_transfer`:

```rust
#[pause(except(roles(Role::DAO)))]
pub fn finish_withdraw_v2(
    &mut self,
    #[serializer(borsh)] sender_id: &AccountId,
    #[serializer(borsh)] amount: u128,
    #[serializer(borsh)] recipient: String,
) { ... }
```

This ensures that when the bridge is paused, **all** transfer-initiation paths are blocked uniformly, regardless of which token contract triggers the call.

### Proof of Concept

1. Admin calls `pa_pause_feature` (or equivalent) to pause the bridge, blocking `ft_on_transfer` for normal users.
2. User holds a legacy bridge token (e.g., `weth.factory.bridge.near`) registered in `deployed_tokens`.
3. User calls `withdraw(amount, eth_recipient)` on the token contract.
4. Token contract burns the user's tokens and cross-contract-calls `finish_withdraw_v2(user.near, amount, "0xRecipient")` on the bridge.
5. `finish_withdraw_v2` executes without any pause check, increments `current_origin_nonce`, inserts a `TransferMessage` into `pending_transfers`, and emits `InitTransferEvent`.
6. The transfer is now pending on-chain despite the bridge being paused, and the user's tokens are already burned — the pause has been bypassed. [2](#0-1)

### Citations

**File:** near/omni-bridge/src/lib.rs (L252-253)
```rust
    #[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) {
```

**File:** near/omni-bridge/src/lib.rs (L444-447)
```rust
    #[payable]
    #[trusted_relayer]
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

**File:** near/omni-bridge/src/lib.rs (L1356-1358)
```rust
    pub fn is_deployed_token(&self, token: &AccountId) -> bool {
        self.deployed_tokens.contains(token) || self.deployed_tokens_v2.contains_key(token)
    }
```
