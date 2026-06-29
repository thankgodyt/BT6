### Title
Unvalidated Destination Chain in `init_transfer` Allows Permanent Locking of User Funds — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

The `init_transfer` function accepts a user-supplied `recipient` whose embedded chain kind is only checked to be non-`Near`. No validation is performed against the set of chains that actually have a registered factory or token mapping. A user who specifies a recipient on an unsupported or not-yet-deployed chain (e.g., `Fogo`, `Abs`, `HyperEvm`, `Strk`) will have their tokens immediately locked or burned, while the resulting pending transfer can never be completed or cancelled, causing permanent loss of funds.

---

### Finding Description

`ft_on_transfer` is the public entry point for all NEAR-side bridge operations. When a user calls `ft_transfer_call` on any NEP-141 token with a `BridgeOnTransferMsg::InitTransfer` payload, execution reaches `init_transfer`: [1](#0-0) 

```rust
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
```

This is the **only** chain-level validation. The `ChainKind` enum enumerates every chain the bridge is aware of, including chains that may not yet have a factory registered on-chain: [2](#0-1) 

After this single check, the transfer message is stored in `pending_transfers` and the user's tokens are locked or burned immediately via `init_transfer_internal`. No check is made against `self.factories` (the map of chain → registered factory address) or `self.token_id_to_address` (the map of (chain, token) → foreign address).

When a relayer subsequently calls `sign_transfer` for this transfer, execution reaches: [3](#0-2) 

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

Because no token address is registered for the unsupported destination chain, this panics. The panic occurs **before** the MPC signing call, so `sign_transfer_callback` is never reached. The transfer remains in `pending_transfers` indefinitely.

There is no public `cancel_transfer` or refund function. The only paths that remove a transfer from `pending_transfers` are `sign_transfer_callback` (only on success with zero fee) and `claim_fee_callback` (requires a valid proof from the destination chain, which does not exist for an unsupported chain): [4](#0-3) [5](#0-4) 

---

### Impact Explanation

Any user who initiates a transfer with a `recipient` on a chain that has no registered factory (e.g., `ChainKind::Fogo`, `ChainKind::Abs`, or any chain added to the enum before its factory is deployed) will have their tokens permanently locked in the bridge with no recovery path. This constitutes a direct, irreversible loss of bridged funds for the affected user.

---

### Likelihood Explanation

The entry path is fully unprivileged: any token holder can call `ft_transfer_call` on any NEP-141 token, specifying the bridge as receiver and an `InitTransfer` message with an arbitrary `ChainKind` recipient. The `ChainKind` enum is a small, fixed set of named variants, so a user or a buggy front-end can easily select a chain that is recognized by the type system but has no factory registered. No special role or key is required.

---

### Recommendation

Add a factory-existence check inside `init_transfer` before locking any tokens:

```rust
require!(
    self.factories.contains_key(&init_transfer_msg.get_destination_chain()),
    BridgeError::InvalidRecipientChain.as_ref()
);
```

Additionally, consider adding a `cancel_transfer` function that allows the original sender to reclaim locked tokens for transfers that have been pending beyond a timeout, as a defense-in-depth measure.

---

### Proof of Concept

1. Assume `ChainKind::Fogo` has no factory registered in `self.factories`.
2. User calls `ft_transfer_call` on a NEAR NEP-141 token with:
   - `receiver_id`: omni-bridge contract
   - `msg`: `BridgeOnTransferMsg::InitTransfer(InitTransferMsg { recipient: OmniAddress::Sol(<fogo_address>), ... })` — using any `ChainKind` variant without a factory.
3. `ft_on_transfer` → `init_transfer` executes. The only check (`recipient.get_chain() != ChainKind::Near`) passes. [1](#0-0) 
4. `init_transfer_internal` is called; user's tokens are locked/burned. The transfer is inserted into `pending_transfers`.
5. A relayer calls `sign_transfer` for this transfer ID.
6. `get_token_address(ChainKind::Fogo, token_id)` returns `None`; the contract panics with `FailedToGetTokenAddress`. [3](#0-2) 
7. The transfer remains in `pending_transfers` forever. No cancel or refund path exists. User's tokens are permanently lost.

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

**File:** near/omni-bridge/src/lib.rs (L1094-1094)
```rust
        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);
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
