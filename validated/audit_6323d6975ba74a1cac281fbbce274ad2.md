### Title
Missing Destination-Chain Token Registration Validation in `init_transfer` Enables Permanent Fund Loss — (File: `near/omni-bridge/src/lib.rs`)

### Summary
The `init_transfer` function on the NEAR omni-bridge contract accepts and finalizes outbound transfer requests without verifying that the specified destination chain has a registered token mapping. For bridge-deployed tokens, this causes irreversible token burns with no path to completion, permanently destroying user funds.

### Finding Description
`init_transfer` (the internal handler called from `ft_on_transfer`) performs only one chain-level check: it rejects `ChainKind::Near` as a destination. [1](#0-0) 

No check is made that:
- the destination chain has a registered factory (`self.factories`), or
- the token has a registered address for that chain (`self.token_id_to_address`).

The function then unconditionally proceeds to `init_transfer_internal`: [2](#0-1) 

Inside `init_transfer_internal`, `burn_tokens_if_needed` is called for any token that is a bridge-deployed token: [3](#0-2) 

The burn is dispatched with `.detach()`, meaning it fires regardless of what happens next. The transfer message is then stored in `pending_transfers` and the function returns `U128(0)` — signalling to the NEP-141 token contract that **zero tokens should be refunded**.

Later, when a relayer calls `sign_transfer`, it attempts to resolve the token address for the destination chain: [4](#0-3) 

If no mapping exists (because the token was never registered for that chain), the call panics with `FailedToGetTokenAddress`. The transfer remains in `pending_transfers` indefinitely — there is no user-accessible cancellation path. The only recovery route is DAO intervention via `transfer_token_as_dao`, which cannot un-burn already-destroyed tokens.

The `token_id_to_address` map is populated only through admin-gated operations (`deploy_token`, `bind_token`, `add_factory`): [5](#0-4) 

### Impact Explanation
A user who holds a bridge-deployed token (e.g., a wrapped asset minted by the bridge on NEAR) and initiates a transfer to a chain where that token has no registered address will have their tokens permanently burned. The `InitTransferEvent` is emitted, the NEP-141 contract is told to keep the tokens (refund = 0), the burn fires asynchronously, and no relayer can ever call `sign_transfer` successfully for that transfer. The funds are unrecoverable. This constitutes permanent loss of bridged funds, which is within the critical impact scope.

### Likelihood Explanation
Any unprivileged user can trigger this by calling `ft_transfer_call` on a bridge-deployed token with an `InitTransferMsg` whose `recipient` resolves to a chain where the token is not registered. No admin compromise, key leak, or social engineering is required — only a user specifying a valid but unsupported destination chain (e.g., `strk:0x...` for a token not yet deployed on Starknet). The `OmniAddress` parser accepts all supported chain variants without checking registration state: [6](#0-5) 

### Recommendation
Before burning or locking tokens in `init_transfer_internal`, verify that the destination chain has both a registered factory and a registered token address:

```rust
require!(
    self.factories.get(&transfer_message.get_destination_chain()).is_some(),
    BridgeError::UnknownFactory.as_ref()
);
require!(
    self.get_token_address(
        transfer_message.get_destination_chain(),
        self.get_token_id(&transfer_message.token),
    ).is_some(),
    BridgeError::FailedToGetTokenAddress.as_ref()
);
```

This check should be placed in `init_transfer` (before storage allocation) so that the NEP-141 `ft_transfer_call` is fully reverted and the user's tokens are returned.

### Proof of Concept
1. Deploy a bridge-deployed token `wrapped.near` registered only for `ChainKind::Eth`.
2. Call `ft_transfer_call` on `wrapped.near` targeting the bridge, with message:
   ```json
   {"InitTransfer": {"recipient": "strk:0xdeadbeef...", "fee": "0", "native_token_fee": "0"}}
   ```
3. `init_transfer` passes the `ChainKind::Near` check (destination is Starknet).
4. `init_transfer_internal` stores the transfer and calls `burn_tokens_if_needed` — tokens are burned.
5. `ft_transfer_call` receives refund = 0; user balance is debited.
6. Any relayer calling `sign_transfer` for this `TransferId` panics at `get_token_address` (no Starknet mapping for `wrapped.near`).
7. Transfer remains in `pending_transfers` forever; burned tokens are unrecoverable. [7](#0-6) [8](#0-7)

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

**File:** near/omni-bridge/src/lib.rs (L523-557)
```rust
    fn init_transfer(
        &mut self,
        sender_id: AccountId,
        signer_id: AccountId,
        token_id: AccountId,
        amount: U128,
        init_transfer_msg: InitTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
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

**File:** near/omni-bridge/src/lib.rs (L1501-1504)
```rust
    #[access_control_any(roles(Role::DAO))]
    pub fn add_factory(&mut self, address: OmniAddress) {
        self.factories.insert(&(&address).into(), &address);
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

**File:** near/omni-bridge/src/lib.rs (L1829-1865)
```rust
    fn init_transfer_internal(
        &mut self,
        transfer_message: TransferMessage,
        storage_owner: AccountId,
    ) -> U128 {
        let required_storage_balance = self
            .add_transfer_message(transfer_message.clone(), storage_owner.clone())
            .saturating_add(NearToken::from_yoctonear(transfer_message.fee.native_fee.0));

        if self
            .try_update_storage_balance(
                storage_owner,
                required_storage_balance,
                NearToken::from_yoctonear(0),
            )
            .is_err()
        {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
        } else {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
        U128(0)
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
