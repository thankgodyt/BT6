Audit Report

## Title
`init_transfer` accepts transfers to chains with no registered token address, permanently destroying or freezing user funds - (File: `near/omni-bridge/src/lib.rs`)

## Summary
`init_transfer` (invoked via `ft_on_transfer`) performs no check that the transferred token has a registered address on the destination chain before burning or locking user tokens. Any user can call `ft_transfer_call` targeting a `ChainKind` where the token has no `token_id_to_address` entry. For deployed (bridged) tokens the tokens are immediately burned; for native NEAR tokens they are permanently frozen in the bridge contract. Because `sign_transfer` unconditionally panics when `get_token_address` returns `None`, the pending transfer can never be completed, and no user-callable cancellation path exists.

## Finding Description

`init_transfer` enforces only two preconditions before accepting tokens:

```rust
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
// ...
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [1](#0-0) 

There is no call to `get_token_address` to verify the token is registered on the destination chain. `init_transfer_internal` then unconditionally calls `burn_tokens_if_needed` for deployed tokens and `lock_tokens_if_needed` for native tokens:

```rust
if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
    self.lock_tokens_if_needed(
        transfer_message.get_destination_chain(),
        &token_id,
        transfer_message.amount.0,
    );
}
``` [2](#0-1) 

`burn_tokens_if_needed` fires a detached `burn` cross-contract call for any token in `deployed_tokens` / `deployed_tokens_v2`: [3](#0-2) 

`lock_tokens_if_needed` silently returns `Unchanged` when no entry exists in `locked_tokens` for the `(chain_kind, token_id)` key, so accounting is not updated even as the burn proceeds: [4](#0-3) 

The only place where token-address registration is enforced for outgoing transfers is `sign_transfer`, a trusted-relayer-only function that panics with `ERR_FAILED_TO_GET_TOKEN_ADDRESS` when `get_token_address` returns `None`: [5](#0-4) 

`get_token_address` performs a plain map lookup and returns `None` for any unregistered `(ChainKind, AccountId)` pair: [6](#0-5) 

The only privileged recovery path is `transfer_token_as_dao`, which is restricted to the `DAO` role and cannot be invoked by the affected user: [7](#0-6) 

The `ChainKind` enum includes newer chains (`Fogo`, `HyperEvm`, `Abs`, `Strk`) that may not have all tokens registered, and `OmniAddress` is parsed directly from a user-supplied string in `ft_transfer_call`, making this path fully user-reachable. [8](#0-7) 

## Impact Explanation

Two concrete loss scenarios exist, both matching the critical impact class of permanent freezing or destruction of bridged funds:

- **Deployed (bridged) tokens**: `burn_tokens_if_needed` issues a detached `burn` call against the token contract. The bridge contract holds the tokens (deposited via `ft_transfer_call`) and the burn succeeds. The tokens are permanently destroyed with no on-chain recovery path for the user.
- **Native NEAR tokens**: No burn occurs, but the tokens remain in the bridge contract indefinitely. `sign_transfer` always panics for this transfer ID, so the transfer can never be finalized. Without DAO intervention via `transfer_token_as_dao`, the tokens are permanently frozen.

Both outcomes match the allowed critical impact: permanent freezing or loss of bridged funds across supported chains.

## Likelihood Explanation

The exploit requires no special privileges. Any token holder can trigger it by calling `ft_transfer_call` on a supported token contract with a recipient address on any chain where that token has no registered address (e.g., `fogo:BXss9YNCX2p6VPf2Em54pHXkXnC2FPBeZgbB9fY1cuBR` for a token only registered on `Eth`). The `OmniAddress` type accepts all `ChainKind` variants via string parsing, and the bridge contract's `ft_on_transfer` is a public callback. The condition is easily triggered by mistake (user selects wrong destination chain) or intentionally by a griefing attacker targeting other users' funds if a shared bridge account is involved. The attack is repeatable and requires no coordination.

## Recommendation

Add a validation in `init_transfer` (before storage deduction and before any burn/lock operations) that checks whether the token has a registered address on the destination chain:

```rust
require!(
    self.get_token_address(
        init_transfer_msg.get_destination_chain(),
        token_id.clone(),
    ).is_some(),
    BridgeError::TokenNotFound.as_ref()
);
```

Placing this check before `init_transfer_internal` is called ensures that `ft_on_transfer` returns the full `amount` as a refund when the check fails, so the token contract returns the tokens to the sender.

## Proof of Concept

1. Token `eth-token.near` is a deployed token registered only for `ChainKind::Eth` (entry exists in `token_id_to_address` for `(Eth, eth-token.near)` but not for `(Fogo, eth-token.near)`).
2. User calls `ft_transfer_call` on `eth-token.near`:
   ```json
   {
     "receiver_id": "omni-bridge.near",
     "amount": "1000000",
     "msg": "{\"InitTransfer\":{\"recipient\":\"fogo:BXss9YNCX2p6VPf2Em54pHXkXnC2FPBeZgbB9fY1cuBR\",\"fee\":\"0\",\"native_token_fee\":\"0\"}}"
   }
   ```
3. `ft_on_transfer` dispatches to `init_transfer`. Both checks pass: destination is not `Near`, fee (0) < amount (1000000).
4. `init_transfer_internal` is called. Storage balance check passes.
5. `burn_tokens_if_needed("eth-token.near", 1000000)` fires a detached `burn` call — tokens are destroyed.
6. `lock_tokens_if_needed(Fogo, "eth-token.near", 1000000)`: origin chain is `Eth` ≠ `Fogo`, so `lock_tokens` is called; no `(Fogo, eth-token.near)` entry exists in `locked_tokens`, returns `Unchanged`.
7. `InitTransferEvent` is emitted; `ft_on_transfer` returns `U128(0)` — no refund to user.
8. Any relayer calling `sign_transfer` on this transfer ID panics with `ERR_FAILED_TO_GET_TOKEN_ADDRESS`.
9. Tokens are permanently destroyed; the pending transfer entry is orphaned.

A unit test can be written mirroring `test_init_transfer_locks_other_tokens_for_deployed_token` but targeting a chain with no `token_id_to_address` entry, asserting that `burn_tokens_if_needed` is called and `sign_transfer` panics.

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

**File:** near/omni-bridge/src/lib.rs (L531-557)
```rust
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );

        self.current_origin_nonce += 1;
        let destination_nonce =
            self.get_next_destination_nonce(init_transfer_msg.get_destination_chain());

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
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
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

**File:** near/omni-bridge/src/lib.rs (L1512-1529)
```rust
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

**File:** near/omni-bridge/src/token_lock.rs (L54-57)
```rust
        let key = (chain_kind, token_id.clone());
        let Some(current_amount) = self.locked_tokens.get(&key) else {
            return LockAction::Unchanged;
        };
```

**File:** near/omni-types/src/lib.rs (L392-411)
```rust
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (chain, recipient) = input.split_once(':').unwrap_or(("eth", input));

        match chain {
            "eth" => Ok(Self::Eth(recipient.parse().map_err(stringify)?)),
            "near" => Ok(Self::Near(recipient.parse().map_err(stringify)?)),
            "sol" => Ok(Self::Sol(recipient.parse().map_err(stringify)?)),
            "arb" => Ok(Self::Arb(recipient.parse().map_err(stringify)?)),
            "base" => Ok(Self::Base(recipient.parse().map_err(stringify)?)),
            "bnb" => Ok(Self::Bnb(recipient.parse().map_err(stringify)?)),
            "pol" => Ok(Self::Pol(recipient.parse().map_err(stringify)?)),
            "hlevm" => Ok(Self::HyperEvm(recipient.parse().map_err(stringify)?)),
            "abs" => Ok(Self::Abs(recipient.parse().map_err(stringify)?)),
            "btc" => Ok(Self::Btc(recipient.to_string())),
            "zcash" => Ok(Self::Zcash(recipient.to_string())),
            "strk" => Ok(Self::Strk(recipient.parse().map_err(stringify)?)),
            "fogo" => Ok(Self::Fogo(recipient.parse().map_err(stringify)?)),
            _ => Err(format!("Chain {chain} is not supported")),
        }
    }
```
