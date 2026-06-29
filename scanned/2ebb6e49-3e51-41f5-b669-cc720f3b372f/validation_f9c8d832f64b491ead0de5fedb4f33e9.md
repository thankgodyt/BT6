### Title
No Cancel/Refund Mechanism for Pending Transfers Causes Permanent Fund Freezing - (File: near/omni-bridge/src/lib.rs)

### Summary
The NEAR Omni Bridge `init_transfer` flow consumes user tokens into the bridge contract and stores the transfer in `pending_transfers`, but provides no cancellation or refund path. If a transfer can never be completed — for example because the token is not registered on the destination chain, causing every `sign_transfer` call to panic — the user's funds are permanently frozen with no recovery mechanism.

### Finding Description

When a user calls `ft_transfer_call` on a NEP-141 token with the bridge as receiver, the bridge's `ft_on_transfer` dispatches to `init_transfer`: [1](#0-0) 

`init_transfer` validates only that the recipient chain is not NEAR, then unconditionally stores the `TransferMessage` in `pending_transfers` and returns `U128(0)` (consuming all tokens): [2](#0-1) 

There is no validation that the token is registered on the destination chain at deposit time. Later, when a relayer calls `sign_transfer`, the contract attempts to look up the token address for the destination chain and panics if it is absent: [3](#0-2) 

The only code paths that remove a transfer from `pending_transfers` are:
1. `sign_transfer_callback` — only when `fee.is_zero()` **and** MPC signing succeeds.
2. `claim_fee_callback` — only after a successful on-chain proof of finalization. [4](#0-3) 

No `cancel_transfer`, `refund_transfer`, or equivalent function exists anywhere in the contract. The `pending_transfers` map has no expiry or user-initiated removal path. [5](#0-4) 

### Impact Explanation

A user who initiates a transfer to a destination chain where the token is not yet registered (or to a chain that later becomes unsupported) will have their tokens permanently locked in the bridge. `sign_transfer` will always panic at `get_token_address`, so the transfer can never be signed, and no other code path removes it from `pending_transfers` or returns the tokens. This constitutes **permanent freezing of bridged funds**, matching the critical/medium impact class of the reference report.

### Likelihood Explanation

The scenario is reachable by any unprivileged user without admin involvement:
- A user sends tokens via `ft_transfer_call` specifying a recipient on a chain where the token mapping has not yet been registered via `bind_token` or `deploy_token`.
- The bridge accepts the deposit, increments the nonce, and stores the transfer.
- Every subsequent `sign_transfer` call panics, and no relayer can ever complete the transfer.
- The user has no recourse.

This is a realistic mistake, especially for newly supported chains or tokens that are in the process of being onboarded.

### Recommendation

1. **Add a `cancel_transfer` function** that allows the original sender (stored as `transfer.sender`) to remove a pending transfer from `pending_transfers` and receive a refund of the locked tokens, provided the transfer has not yet been signed/finalized.
2. **Add a pre-flight check in `init_transfer`** that verifies the token is registered on the destination chain before consuming the user's tokens.
3. Optionally, add a time-based expiry so that transfers that have been pending for longer than a configurable window can be cancelled.

### Proof of Concept

1. Token `usdc.near` is registered on `ChainKind::Eth` but not on `ChainKind::Arb`.
2. User calls `usdc.near::ft_transfer_call(bridge, 1000, msg)` where `msg` specifies a recipient on Arbitrum.
3. `ft_on_transfer` → `init_transfer` stores the transfer in `pending_transfers` and returns `U128(0)` — tokens are consumed.
4. Relayer calls `sign_transfer(transfer_id, ...)`.
5. Inside `sign_transfer`, `get_token_address(ChainKind::Arb, usdc.near)` returns `None`, triggering `env::panic_str(BridgeError::FailedToGetTokenAddress)`.
6. The transfer remains in `pending_transfers` indefinitely. The user's 1000 USDC is permanently locked. No cancel path exists. [6](#0-5) [7](#0-6)

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

**File:** near/omni-bridge/src/lib.rs (L523-534)
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
```

**File:** near/omni-bridge/src/lib.rs (L536-557)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L648-668)
```rust
    #[private]
    pub fn sign_transfer_callback(
        &mut self,
        #[callback_result] call_result: Result<SignatureResponse, PromiseError>,
        #[serializer(borsh)] message_payload: TransferMessagePayload,
        #[serializer(borsh)] fee: &Fee,
    ) {
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }

            env::log_str(
                &OmniBridgeEvent::SignTransferEvent {
                    signature,
                    message_payload,
                }
                .to_log_string(),
            );
        }
    }
```

**File:** near/omni-bridge/src/storage.rs (L62-69)
```rust
#[allow(clippy::module_name_repetitions)]
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub enum TransferMessageStorage {
    V0(TransferMessageStorageValueV0),
    V1(TransferMessageStorageValueV1),
    V2(TransferMessageStorageValue),
}
```
