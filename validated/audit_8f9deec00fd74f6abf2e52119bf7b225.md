Audit Report

## Title
Tokens Burned/Locked Before Destination-Chain Validation Causes Permanent Fund Loss - (File: `near/omni-bridge/src/lib.rs`)

## Summary
`init_transfer` validates only that the destination chain is not NEAR, but does not verify that the destination chain has a registered factory or that the token is registered for that chain. For deployed (bridged) tokens, `burn_tokens_if_needed` immediately destroys tokens via a detached promise before any destination-chain validity is confirmed. For native NEAR tokens, the funds are silently held by the bridge with no user recovery path. In both cases, every subsequent relayer call to `sign_transfer` panics, leaving the transfer permanently stuck.

## Finding Description
`init_transfer` performs only one destination-chain guard:

```rust
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
``` [1](#0-0) 

There is no check that `self.factories.get(&destination_chain).is_some()` or that `self.token_id_to_address.get(&(destination_chain, token_id)).is_some()`. Execution proceeds into `init_transfer_internal`, which calls:

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(
    transfer_message.get_destination_chain(),
    &token_id,
    transfer_message.amount.0,
);
``` [2](#0-1) 

`burn_tokens_if_needed` fires a detached, fire-and-forget burn for any deployed token — the tokens are destroyed before any destination-chain validity is confirmed:

```rust
fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
    if self.is_deployed_token(&token) {
        ext_token::ext(token)
            .with_static_gas(BURN_TOKEN_GAS)
            .burn(amount)
            .detach();
    }
}
``` [3](#0-2) 

For native NEAR tokens (not deployed), `lock_tokens_if_needed` calls `lock_tokens`, which silently returns `LockAction::Unchanged` when the `(chain_kind, token_id)` key is absent from `locked_tokens`:

```rust
let Some(current_amount) = self.locked_tokens.get(&key) else {
    return LockAction::Unchanged;
};
``` [4](#0-3) 

The destination-chain token address lookup only happens later in `sign_transfer`, called by a trusted relayer:

```rust
let token_address = self
    .get_token_address(
        transfer_message.get_destination_chain(),
        self.get_token_id(&transfer_message.token),
    )
    .unwrap_or_else(|| {
        env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
    });
``` [5](#0-4) 

`get_token_address` is a plain map lookup returning `None` for any unregistered chain/token pair: [6](#0-5) 

When `sign_transfer` panics, the transfer record remains in `pending_transfers` indefinitely. There is no user-accessible cancel or refund function in the contract. The `transfer_token_as_dao` escape hatch is DAO-only and cannot recover burned tokens. [7](#0-6) 

## Impact Explanation
This is a **Critical** impact matching "permanent freezing of bridged funds." For deployed (bridged) tokens (e.g., ETH-originated tokens held on NEAR), `burn_tokens_if_needed` destroys them immediately and irreversibly via a detached promise — there is no recovery path. For native NEAR tokens, the funds are transferred into the bridge via `ft_transfer_call`, `init_transfer_internal` returns `U128(0)` (no refund), and the tokens are held by the bridge contract but untracked in `locked_tokens` and permanently inaccessible to the user. In both cases the transfer is permanently stuck and user funds are lost.

## Likelihood Explanation
Any unprivileged user can trigger this by calling `ft_transfer_call` on any NEP-141 token with an `InitTransfer` message whose `recipient` encodes a chain for which the token has not been registered via `bind_token` / `deploy_token`. The bridge supports many chains (`Eth`, `Sol`, `Arb`, `Base`, `Bnb`, `Pol`, `Abs`, `HyperEvm`, `Strk`, `Fogo`, `Btc`, `Zcash`), and a token may be registered on some but not all of them. A user who picks a valid-looking chain enum value for an unregistered token-chain pair will silently lose funds. No special privileges are required; the only precondition is that the user holds a token that is either deployed or native to NEAR.

## Recommendation
Add upfront validation in `init_transfer` (before `init_transfer_internal` is entered) that:
1. Confirms `self.token_id_to_address.get(&(destination_chain, token_id)).is_some()`, and optionally
2. Confirms `self.factories.get(&destination_chain).is_some()`.

Both checks must occur before any token state change, mirroring the pattern already used in `sign_transfer` but moved to the point where the transfer is first accepted.

## Proof of Concept
1. Token `usdc.near` is registered for `ChainKind::Eth` but **not** for `ChainKind::Sol`.
2. User calls `usdc.near::ft_transfer_call(bridge, amount, InitTransfer { recipient: OmniAddress::Sol(<valid_sol_addr>), fee: 0, ... })`.
3. `init_transfer` passes the only guard (`recipient.get_chain() != Near`).
4. `init_transfer_internal` is entered. If `usdc.near` is a deployed token, `burn_tokens_if_needed` fires a detached burn — tokens permanently destroyed. If native, tokens are held by the bridge with no tracking entry.
5. `InitTransferEvent` is emitted; transfer stored in `pending_transfers`.
6. Relayer calls `sign_transfer`. `get_token_address(ChainKind::Sol, usdc.near)` returns `None` → panic `ERR_FAILED_TO_GET_TOKEN_ADDRESS`.
7. Transfer is permanently stuck. User's tokens are gone.

A local integration test can reproduce this by: (a) deploying the bridge contract, (b) registering `usdc.near` only for `ChainKind::Eth`, (c) calling `ft_transfer_call` with a Solana recipient, (d) asserting the burn was fired (for deployed tokens) or the balance is held (for native tokens), and (e) asserting that `sign_transfer` panics with `ERR_FAILED_TO_GET_TOKEN_ADDRESS`.

### Citations

**File:** near/omni-bridge/src/lib.rs (L462-469)
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

**File:** near/omni-bridge/src/lib.rs (L531-534)
```rust
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1360-1366)
```rust
    pub fn get_token_address(
        &self,
        chain_kind: ChainKind,
        token: AccountId,
    ) -> Option<OmniAddress> {
        self.token_id_to_address.get(&(chain_kind, token))
    }
```

**File:** near/omni-bridge/src/lib.rs (L1511-1530)
```rust
    #[access_control_any(roles(Role::DAO))]
    pub fn transfer_token_as_dao(
        &mut self,
        token: AccountId,
        amount: U128,
        recipient: AccountId,
        msg: Option<String>,
    ) -> Promise {
        if let Some(msg) = msg {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_CALL_GAS)
                .ft_transfer_call(recipient, amount, None, msg)
        } else {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
        }
    }
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

**File:** near/omni-bridge/src/token_lock.rs (L55-57)
```rust
        let Some(current_amount) = self.locked_tokens.get(&key) else {
            return LockAction::Unchanged;
        };
```
