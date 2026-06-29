### Title
`init_transfer` accepts transfers to chains where the token has no registered address, permanently losing user funds - (File: `near/omni-bridge/src/lib.rs`)

### Summary
The `init_transfer` function in the NEAR omni-bridge contract does not validate that the transferred token has a registered address on the destination chain before burning or locking user tokens. A user can initiate a transfer to any valid `ChainKind` (e.g., `Fogo`, `HyperEvm`, `Abs`, `Strk`) where the token has not yet been deployed or registered. The tokens are burned or permanently locked in the bridge, and the pending transfer can never be completed because `sign_transfer` will always fail.

### Finding Description

`init_transfer` (called via `ft_on_transfer`) performs only two validations before accepting tokens: [1](#0-0) 

```rust
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
```

and a fee-less-than-amount check. There is no check that the token has a registered address on the destination chain via `token_id_to_address`.

`init_transfer_internal` then proceeds to burn deployed tokens and lock accounting: [2](#0-1) 

The `ChainKind` enum has 13 variants, several of which are newer chains: [3](#0-2) 

A token may be registered on `Eth` but not on `Fogo`, `HyperEvm`, `Abs`, or `Strk`. When a user sends tokens to such a chain, `init_transfer_internal` returns `U128(0)` (no refund), the tokens are burned (for deployed/bridged tokens) or held in the bridge (for native tokens), and the `InitTransferEvent` is emitted.

The only place where the token-address registration is checked for outgoing transfers is in `sign_transfer`, which is a trusted-relayer-only function: [4](#0-3) 

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

`get_token_address` returns `None` for unregistered chain/token pairs: [5](#0-4) 

So `sign_transfer` will always panic with `ERR_FAILED_TO_GET_TOKEN_ADDRESS` for this transfer. There is no user-callable cancellation function; the only recovery path is DAO-privileged `transfer_token_as_dao`.

Additionally, `lock_tokens_if_needed` silently returns `Unchanged` if the chain/token key is absent from `locked_tokens`: [6](#0-5) 

So even the accounting is not updated, while the tokens are already burned.

### Impact Explanation

- **Deployed (bridged) tokens**: `burn_tokens_if_needed` is called unconditionally for deployed tokens. The tokens are permanently destroyed with no recovery path.
- **Native NEAR tokens**: Tokens are transferred to the bridge contract via `ft_transfer_call` and held there indefinitely. Without DAO intervention via `transfer_token_as_dao`, they are permanently frozen.

This matches the critical impact class: permanent freezing or loss of bridged funds.

### Likelihood Explanation

The `ChainKind` enum includes newer chains (`Fogo`, `HyperEvm`, `Abs`, `Strk`) that may not have all tokens registered. A user who specifies a recipient address on one of these chains (e.g., `fogo:BXss9YNCX2p6VPf2Em54pHXkXnC2FPBeZgbB9fY1cuBR`) for a token that has only been deployed on `Eth` will trigger this path. The `OmniAddress` type is parsed from a user-supplied string, making this directly user-reachable via `ft_transfer_call`. [7](#0-6) 

### Recommendation

Add a validation in `init_transfer` (or `init_transfer_internal`) that checks whether the token has a registered address on the destination chain before accepting the transfer:

```rust
require!(
    self.get_token_address(
        init_transfer_msg.get_destination_chain(),
        token_id.clone(),
    ).is_some(),
    BridgeError::TokenNotFound.as_ref()
);
```

This check should be placed before the storage balance deduction and before any burn/lock operations, so that the `ft_on_transfer` callback can return the full amount to refund the user.

### Proof of Concept

1. Token `wrapped-eth.near` is a deployed token registered only for `ChainKind::Eth`.
2. User calls `ft_transfer_call` on `wrapped-eth.near` with:
   ```json
   {
     "receiver_id": "omni-bridge.near",
     "amount": "1000000",
     "msg": "{\"InitTransfer\":{\"recipient\":\"fogo:BXss9YNCX2p6VPf2Em54pHXkXnC2FPBeZgbB9fY1cuBR\",\"fee\":\"0\",\"native_token_fee\":\"0\"}}"
   }
   ```
3. `init_transfer` passes both checks (destination is not Near, fee < amount).
4. `init_transfer_internal` calls `burn_tokens_if_needed` — tokens are burned.
5. `lock_tokens_if_needed(ChainKind::Fogo, ...)` returns `Unchanged` (no entry in `locked_tokens`).
6. `InitTransferEvent` is emitted; `ft_on_transfer` returns `U128(0)` — no refund.
7. Any relayer calling `sign_transfer` on this transfer ID panics with `ERR_FAILED_TO_GET_TOKEN_ADDRESS`.
8. Tokens are permanently lost.

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

**File:** near/omni-types/src/lib.rs (L53-83)
```rust
pub enum ChainKind {
    #[default]
    #[serde(alias = "eth")]
    Eth,
    #[serde(alias = "near")]
    Near,
    #[serde(alias = "sol")]
    Sol,
    #[serde(alias = "arb")]
    Arb,
    #[serde(alias = "base")]
    Base,
    #[serde(alias = "bnb")]
    Bnb,
    #[serde(alias = "btc")]
    Btc,
    #[serde(alias = "zcash")]
    Zcash,
    #[serde(alias = "pol")]
    Pol,
    #[serde(rename = "HlEvm")]
    #[serde(alias = "hlevm")]
    #[strum(serialize = "HlEvm")]
    HyperEvm,
    #[serde(alias = "strk")]
    Strk,
    #[serde(alias = "abs")]
    Abs,
    #[serde(alias = "fogo")]
    Fogo,
}
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

**File:** near/omni-bridge/src/token_lock.rs (L55-57)
```rust
        let Some(current_amount) = self.locked_tokens.get(&key) else {
            return LockAction::Unchanged;
        };
```
