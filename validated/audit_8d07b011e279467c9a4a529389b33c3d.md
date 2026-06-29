Audit Report

## Title
`init_transfer` Accepts Unregistered Tokens Without Binding Validation, Causing Permanent Fund Lock - (File: `near/omni-bridge/src/lib.rs`)

## Summary
The `init_transfer` function, invoked via `ft_on_transfer` when a user sends tokens to the bridge, does not verify that the transferred token has a registered cross-chain address binding for the destination chain. Any NEP-141 token can be deposited and a transfer record created, but the transfer can never be completed because `sign_transfer` will always panic for unregistered tokens. No user-accessible cancel or refund path exists, resulting in permanent freezing of the deposited funds.

## Finding Description
When a user calls `ft_transfer_call` on a NEAR token contract targeting the bridge, `ft_on_transfer` dispatches to `init_transfer`. The function constructs a `TransferMessage` with `token: OmniAddress::Near(token_id)` and proceeds to store it via `init_transfer_internal`, returning `U128(0)` to signal that the bridge retains the tokens.

The only validation performed in `init_transfer` is a check that the recipient chain is not NEAR:

```rust
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
```

No check is made against `token_id_to_address` to confirm the token has a registered binding for the destination chain. The transfer is stored and the tokens are locked.

When a relayer subsequently calls `sign_transfer`, it invokes `get_token_address` for the destination chain and the token ID. For an unregistered token, this returns `None` and the contract panics:

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

This panic aborts the signing attempt but does not refund or remove the transfer. The transfer record remains in `pending_transfers` and the tokens remain in the bridge's custody indefinitely.

The `get_token_id` helper for a `Near`-variant address simply returns the account ID directly without any registration check, so it does not catch the unregistered token:

```rust
pub fn get_token_id(&self, address: &OmniAddress) -> AccountId {
    if let OmniAddress::Near(token_account_id) = address {
        token_account_id.clone()  // no registration check
    } else { ... }
}
```

By contrast, `fast_fin_transfer` performs the binding check eagerly before accepting tokens, panicking with `BridgeError::TokenNotFound` if no binding exists — a guard that is entirely absent from `init_transfer`.

No public cancel, withdraw, or rescue function exists for users to recover tokens from a stuck pending transfer. The `remove_transfer_message` path is only reachable through the private `sign_transfer_callback`, which is never reached for unregistered tokens.

## Impact Explanation
This constitutes permanent freezing of bridged funds, which is an explicitly listed Critical impact. Any user who sends an unregistered NEP-141 token to the bridge via `ft_transfer_call` will have their tokens permanently locked in the bridge contract with no recovery path. The bridge accepts and retains the tokens, stores the transfer record, but the transfer can never be finalized or cancelled.

## Likelihood Explanation
The entry path is fully unprivileged: any holder of any NEP-141 token can call `ft_transfer_call` targeting the bridge contract. A user may trigger this accidentally by sending a token before its binding is registered, or by sending a token that was never intended to be bridged. No special role, key, or permission is required. The condition is repeatable and affects any amount of any unregistered token.

## Recommendation
Add a binding validation check at the start of `init_transfer`, before accepting the deposit, to confirm the token has a registered address for the destination chain. If no binding exists, return the full `amount` to trigger a NEP-141 refund:

```rust
fn init_transfer(...) -> PromiseOrPromiseIndexOrValue<U128> {
    require!(
        init_transfer_msg.recipient.get_chain() != ChainKind::Near,
        BridgeError::InvalidRecipientChain.as_ref()
    );

    // Verify the token has a valid binding on the destination chain
    let destination_chain = init_transfer_msg.get_destination_chain();
    if self.get_token_address(destination_chain, token_id.clone()).is_none() {
        return PromiseOrPromiseIndexOrValue::Value(amount);
    }
    // ... rest of function
}
```

This mirrors the early validation already present in `fast_fin_transfer` at lines 758–763.

## Proof of Concept
1. Deploy any NEP-141 token `unregistered.token.near` that has no entry in the bridge's `token_id_to_address` map.
2. Call `ft_transfer_call` on `unregistered.token.near` with `receiver_id = omni.bridge.near`, `amount = 1000000`, and `msg = {"InitTransfer": {"recipient": "0x<eth_address>", "fee": "0", "native_token_fee": "0"}}`.
3. `ft_on_transfer` dispatches to `init_transfer` (line 263) → no binding check → `init_transfer_internal` stores the transfer → `U128(0)` returned → bridge retains the 1,000,000 tokens.
4. Relayer calls `sign_transfer` for the new transfer ID → `get_token_address(Eth, unregistered.token.near)` returns `None` (line 462–469) → contract panics with `FailedToGetTokenAddress` → tokens remain locked.
5. No cancel or refund function exists; tokens are permanently frozen.

A local integration test using `near-workspaces` can reproduce this by: deploying the bridge and a mock NEP-141 token without registering a binding, calling `ft_transfer_call`, asserting the bridge balance increased, then calling `sign_transfer` and asserting it panics, and finally asserting no user-accessible recovery path exists.