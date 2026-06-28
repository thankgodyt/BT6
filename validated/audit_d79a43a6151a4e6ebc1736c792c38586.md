### Title
Transfer to Unconfigured Destination Chain Burns/Locks Tokens Permanently Before Validation - (File: `near/omni-bridge/src/lib.rs`)

### Summary
The NEAR-side `init_transfer` / `init_transfer_internal` flow burns or locks user tokens before verifying that the destination chain has a registered factory or that the token is registered for that chain. When a user specifies a recipient on an unconfigured destination chain, tokens are irreversibly consumed and the transfer becomes permanently unserviceable.

### Finding Description
`init_transfer` (the internal dispatcher called from `ft_on_transfer`) performs only one destination-chain check:

```rust
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
``` [1](#0-0) 

There is no check that `self.factories.get(&destination_chain)` is populated, nor that `self.token_id_to_address.get(&(destination_chain, token_id))` exists. Execution proceeds directly into `init_transfer_internal`:

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(
    transfer_message.get_destination_chain(),
    &token_id,
    transfer_message.amount.0,
);
``` [2](#0-1) 

`burn_tokens_if_needed` issues a fire-and-forget detached burn for any deployed (bridged) token — the tokens are gone before any destination-chain validity is confirmed:

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

The destination-chain token address lookup only happens later, inside `sign_transfer`, called by a trusted relayer:

```rust
let token_address = self
    .get_token_address(
        transfer_message.get_destination_chain(),
        self.get_token_id(&transfer_message.token),
    )
    .unwrap_or_else(|| {
        env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
    });
``` [4](#0-3) 

`get_token_address` is a simple map lookup that returns `None` for any chain/token pair that was never registered:

```rust
pub fn get_token_address(&self, chain_kind: ChainKind, token: AccountId) -> Option<OmniAddress> {
    self.token_id_to_address.get(&(chain_kind, token))
}
``` [5](#0-4) 

When `sign_transfer` panics, the transfer record remains in `pending_transfers` indefinitely. There is no user-accessible cancel or refund function in the contract. The `transfer_token_as_dao` escape hatch is DAO-only and cannot recover burned tokens. [6](#0-5) 

### Impact Explanation
- **Deployed (bridged) tokens** (e.g., ETH-originated tokens held on NEAR): `burn_tokens_if_needed` destroys them immediately via a detached promise. The tokens are permanently destroyed with no recovery path.
- **Native NEAR tokens** (e.g., USDC.near): transferred into the bridge contract via `ft_transfer_call`, then `lock_tokens_if_needed` silently does nothing if the `(chain, token)` key is absent from `locked_tokens`. The tokens are held by the bridge but untracked and unrecoverable by the user.

In both cases the `InitTransferEvent` is emitted, the transfer is stored in `pending_transfers`, and every subsequent relayer call to `sign_transfer` panics with `ERR_FAILED_TO_GET_TOKEN_ADDRESS`. The transfer is permanently stuck and the funds are lost.

### Likelihood Explanation
Any unprivileged user can trigger this by calling `ft_transfer_call` on any NEP-141 token with an `InitTransfer` message whose `recipient` encodes a chain for which the token has not been registered via `bind_token` / `deploy_token`. This is a realistic mistake: the bridge supports many chains (`Eth`, `Sol`, `Arb`, `Base`, `Bnb`, `Pol`, `Abs`, `HyperEvm`, `Strk`, `Fogo`, `Btc`, `Zcash`), and a token may be registered on some but not all of them. A user who picks a valid-looking chain enum value for an unregistered token-chain pair will silently lose funds.

### Recommendation
Add an upfront validation in `init_transfer` (before any token state change) that:
1. Confirms `self.factories.get(&destination_chain).is_some()`, and
2. Confirms `self.token_id_to_address.get(&(destination_chain, token_id)).is_some()`.

Both checks must occur before `init_transfer_internal` is entered, mirroring the pattern already used in `sign_transfer` but moved to the point where the transfer is first accepted.

### Proof of Concept
1. Token `usdc.near` is registered for `ChainKind::Eth` (factory + `token_id_to_address` entry exist) but **not** for `ChainKind::Sol`.
2. User calls `usdc.near::ft_transfer_call(bridge, amount, InitTransfer { recipient: OmniAddress::Sol(<valid_sol_addr>), fee: 0, ... })`.
3. `init_transfer` passes the only guard (`recipient.get_chain() != Near`). [1](#0-0) 
4. `init_transfer_internal` is entered. If `usdc.near` is a deployed token, `burn_tokens_if_needed` fires a detached burn — tokens destroyed. [2](#0-1) 
5. `InitTransferEvent` is emitted; transfer stored in `pending_transfers`.
6. Relayer calls `sign_transfer`. `get_token_address(ChainKind::Sol, usdc.near)` returns `None` → panic `ERR_FAILED_TO_GET_TOKEN_ADDRESS`. [4](#0-3) 
7. Transfer is permanently stuck. User's tokens are gone.

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

**File:** near/omni-bridge/src/lib.rs (L1511-1529)
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
