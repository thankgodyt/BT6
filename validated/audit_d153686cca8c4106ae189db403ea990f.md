Audit Report

## Title
`init_transfer` burns deployed tokens without validating destination chain token registration, causing permanent fund loss - (File: `near/omni-bridge/src/lib.rs`)

## Summary
The `init_transfer` function accepts token transfers to any valid `ChainKind` destination without verifying that the token has a registered address on that chain. For deployed (bridged) tokens, `burn_tokens_if_needed` is called unconditionally, permanently destroying the tokens. The resulting pending transfer can never be completed because `sign_transfer` will always panic when it cannot find the token address for the destination chain, and no user-callable cancellation path exists.

## Finding Description
`init_transfer` (invoked via `ft_on_transfer`) performs only two validations before accepting tokens:

```rust
// near/omni-bridge/src/lib.rs L531-534
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
```

and a fee-less-than-amount check at L554-557. There is no call to `get_token_address` to verify the token is registered on the destination chain.

`init_transfer_internal` then unconditionally calls `burn_tokens_if_needed` for any token in `deployed_tokens`:

```rust
// near/omni-bridge/src/lib.rs L1850-1857
if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
    self.lock_tokens_if_needed(
        transfer_message.get_destination_chain(),
        &token_id,
        transfer_message.amount.0,
    );
}
```

`burn_tokens_if_needed` (L1806-1813) fires a detached `burn` cross-contract call for any token in `deployed_tokens`, with no precondition on destination chain registration. The burn is irreversible.

`lock_tokens_if_needed` (token_lock.rs L96-107) then calls `lock_tokens`, which silently returns `LockAction::Unchanged` if the `(chain_kind, token_id)` key is absent from `locked_tokens` (L55-57) — so even the accounting is skipped while the tokens are already burned.

The only place where destination-chain token registration is checked is in `sign_transfer` (L462-469), which is gated by `#[trusted_relayer]` and calls:

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

`get_token_address` (L1360-1366) returns `None` for any unregistered `(chain_kind, token)` pair, so `sign_transfer` will always panic with `ERR_FAILED_TO_GET_TOKEN_ADDRESS` for this transfer. The pending transfer is permanently stuck.

The only privileged recovery path is `transfer_token_as_dao` (L1511-1529), which is DAO-only and cannot recover burned tokens — it can only transfer tokens held by the bridge contract.

## Impact Explanation
For deployed (bridged) tokens: tokens are permanently destroyed via `burn_tokens_if_needed` with no recovery path, not even for the DAO. This is a direct, irreversible loss of bridged funds. For native NEAR tokens: tokens are transferred to the bridge contract and permanently frozen there without DAO intervention. Both cases match the critical impact class: permanent freezing or loss of bridged funds across supported chains.

## Likelihood Explanation
Any unprivileged user can trigger this via `ft_transfer_call` on any deployed token contract, specifying a recipient on a chain where the token has no registered address (e.g., `fogo:...`, `hlevm:...`, `abs:...`, `strk:...`). The `OmniAddress` type is parsed directly from the user-supplied `msg` string in `ft_on_transfer`. No special privileges, front-running, or external conditions are required. The `ChainKind` enum has 13 variants and tokens are typically registered on only a subset of chains, making the unregistered-chain condition easy to satisfy. The attack is repeatable and affects any amount.

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

This ensures `ft_on_transfer` returns the full token amount as a refund if the destination chain is not supported for the given token.

## Proof of Concept
1. Token `wrapped-eth.near` is a deployed token registered only for `ChainKind::Eth` in `token_id_to_address`.
2. User calls `ft_transfer_call` on `wrapped-eth.near`:
   ```json
   {
     "receiver_id": "omni-bridge.near",
     "amount": "1000000",
     "msg": "{\"InitTransfer\":{\"recipient\":\"fogo:BXss9YNCX2p6VPf2Em54pHXkXnC2FPBeZgbB9fY1cuBR\",\"fee\":\"0\",\"native_token_fee\":\"0\"}}"
   }
   ```
3. `init_transfer` passes both checks: destination is not `Near`, fee (0) < amount (1000000).
4. `init_transfer_internal` is called; `burn_tokens_if_needed("wrapped-eth.near", 1000000)` fires a detached `burn` call — tokens are permanently destroyed.
5. `lock_tokens_if_needed(ChainKind::Fogo, "wrapped-eth.near", 1000000)` returns `Unchanged` (no entry in `locked_tokens` for `(Fogo, wrapped-eth.near)`).
6. `InitTransferEvent` is emitted; `ft_on_transfer` returns `U128(0)` — no refund to user.
7. Any trusted relayer calling `sign_transfer` on this transfer ID panics with `ERR_FAILED_TO_GET_TOKEN_ADDRESS`.
8. `transfer_token_as_dao` cannot recover burned tokens.
9. Tokens are permanently lost.

A unit test can be written by extending the existing test suite in `near/omni-bridge/src/tests/lib_test.rs`: register a deployed token only for `ChainKind::Eth`, call `run_ft_on_transfer` with a `Fogo` recipient, and assert that `ft_on_transfer` returns `U128(0)` (no refund) while the token balance is reduced — confirming the burn occurred with no recovery path.