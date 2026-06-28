### Title
Tokens Permanently Frozen When Initiating Transfer to Chain Where Token Is Not Registered - (`near/omni-bridge/src/lib.rs`)

### Summary

The NEAR `omni-bridge` contract's `init_transfer` path burns or locks user tokens on NEAR before verifying that the token is registered for the destination chain. If the token has no address mapping for the destination chain, the subsequent `sign_transfer` call always panics with `ERR_FAILED_TO_GET_TOKEN_ADDRESS`, and no recovery mechanism exists. The result is permanent freezing of the user's funds.

### Finding Description

When a user bridges a NEAR token to a foreign chain, the flow is:

1. User calls `ft_transfer_call` on the NEP-141 token contract, which triggers `ft_on_transfer` on the bridge.
2. `ft_on_transfer` calls `init_transfer`, which calls `init_transfer_internal`.
3. `init_transfer_internal` burns (for deployed/bridge-minted tokens) or locks (for native NEAR tokens) the user's tokens and stores a `TransferMessage` in `pending_transfers`. It returns `U128(0)`, signalling to the token contract that all tokens were consumed.
4. Later, a relayer calls `sign_transfer` to obtain an MPC signature for the destination chain.

The critical gap is in step 2–3: `init_transfer` only validates that the recipient chain is not NEAR:

```rust
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
``` [1](#0-0) 

It does **not** check whether the token has a registered address on the destination chain. Tokens are burned/locked unconditionally:

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(
    transfer_message.get_destination_chain(),
    &token_id,
    transfer_message.amount.0,
);
``` [2](#0-1) 

Then, when `sign_transfer` is called, it attempts to resolve the token address for the destination chain:

```rust
let token_address = self
    .get_token_address(
        transfer_message.get_destination_chain(),
        self.get_token_id(&transfer_message.token),
    )
    .unwrap_or_else(|| {
        env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
    });
``` [3](#0-2) 

If the token is not registered for that chain, this panics. Because `sign_transfer` is a separate transaction from `init_transfer_internal`, the panic only reverts the `sign_transfer` call — the prior burn/lock and the `pending_transfers` entry are already committed and cannot be undone.

There is no `cancel_transfer`, `refund_transfer`, or any other function that removes a `pending_transfers` entry without a successful MPC signing. The `remove_transfer_message` path inside `sign_transfer_callback` is only reachable if the MPC signing succeeds:

```rust
if let Ok(signature) = call_result {
    if fee.is_zero() {
        self.remove_transfer_message(message_payload.transfer_id);
    }
    ...
}
``` [4](#0-3) 

### Impact Explanation

- **For deployed (bridge-minted) tokens**: `burn_tokens_if_needed` fires a detached burn call. The tokens are destroyed on NEAR with no corresponding release on the destination chain. Loss is permanent and irreversible.
- **For native NEAR tokens**: tokens are locked inside the bridge contract indefinitely. An admin could theoretically register the token for the destination chain after the fact, but this requires out-of-band coordination, is not guaranteed, and leaves user funds at risk for an unbounded period.

In both cases the user's funds are frozen with no self-service recovery path.

### Likelihood Explanation

The bridge supports a large and growing set of destination chains (Eth, Arb, Base, Bnb, Pol, HyperEvm, Abs, Sol, Fogo, Btc, Zcash, Strk). [5](#0-4) 

A token is commonly registered for only a subset of these chains. Any user who specifies a recipient on a chain where their token is not yet registered will trigger this path. This is a realistic accidental scenario (e.g., a user holds a NEAR-side bridge token that originated from Ethereum and attempts to send it to Arbitrum instead of back to Ethereum).

### Recommendation

Add a pre-flight check in `init_transfer` (before burning/locking) that verifies the token has a registered address for the destination chain. If the check fails, return the full `amount` to refund the user rather than consuming the tokens:

```rust
// Before burning/locking, verify token is registered for destination chain
let destination_chain = init_transfer_msg.recipient.get_chain();
if self.get_token_address(destination_chain, token_id.clone()).is_none() {
    return PromiseOrPromiseIndexOrValue::Value(amount); // refund
}
```

Additionally, consider adding an emergency `cancel_transfer` function (callable by the sender or DAO) that removes a stuck `pending_transfers` entry and refunds/re-mints the locked/burned tokens.

### Proof of Concept

1. Token `foo.near` is registered for `ChainKind::Eth` but not for `ChainKind::Arb`.
2. User calls `ft_transfer_call` on `foo.near` with `receiver_id = omni-bridge.near` and `msg = {"recipient": "arb:0xRecipient", "fee": "0", ...}`.
3. `ft_on_transfer` → `init_transfer` → `init_transfer_internal` executes:
   - `burn_tokens_if_needed` burns the user's tokens (if `foo.near` is a deployed token).
   - `lock_tokens_if_needed` locks the tokens (if native).
   - Returns `U128(0)` — tokens consumed.
4. Relayer calls `sign_transfer` for the stuck transfer.
5. `get_token_address(ChainKind::Arb, "foo.near")` returns `None`.
6. `env::panic_str(BridgeError::FailedToGetTokenAddress...)` — transaction reverts.
7. `pending_transfers` entry remains; tokens remain burned/locked.
8. Steps 4–7 repeat indefinitely. No recovery path exists for the user. [6](#0-5) [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L462-474)
```rust
        let token_address = self
            .get_token_address(
                transfer_message.get_destination_chain(),
                self.get_token_id(&transfer_message.token),
            )
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });

        let decimals = self
            .token_decimals
            .get(&token_address)
            .near_expect(BridgeError::TokenDecimalsNotFound);
```

**File:** near/omni-bridge/src/lib.rs (L531-534)
```rust
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L655-667)
```rust
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
