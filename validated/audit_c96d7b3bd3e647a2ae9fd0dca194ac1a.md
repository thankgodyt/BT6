Audit Report

## Title
`init_transfer` accepts transfers to chains with no registered token address, permanently destroying or freezing user funds - (File: `near/omni-bridge/src/lib.rs`)

## Summary
The `init_transfer` function performs no validation that the transferred token has a registered address on the destination chain before accepting and processing the transfer. For deployed (bridged) tokens, `burn_tokens_if_needed` is called unconditionally, permanently destroying the tokens. For native NEAR tokens, they are held in the bridge contract with no user-callable recovery path. In both cases, `sign_transfer` will always panic with `ERR_FAILED_TO_GET_TOKEN_ADDRESS`, making the pending transfer permanently uncompletable.

## Finding Description

`init_transfer` (called via `ft_on_transfer`) performs only two validations before accepting tokens:

```rust
// near/omni-bridge/src/lib.rs L531-534
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
```

and a fee-less-than-amount check at L554-557. There is no check that `self.token_id_to_address.get(&(destination_chain, token_id))` returns `Some`.

`init_transfer_internal` (L1829-1865) then unconditionally:
1. Calls `burn_tokens_if_needed` (L1851) — for any token in `deployed_tokens` or `deployed_tokens_v2`, this fires a detached `burn` promise, permanently destroying the tokens.
2. Calls `lock_tokens_if_needed` (L1853-1857) — for an unregistered chain/token pair, `lock_tokens` (token_lock.rs L55-57) finds no entry in `locked_tokens` and silently returns `LockAction::Unchanged`, so accounting is never updated.
3. Returns `U128(0)` — no refund to the caller.

Later, any relayer calling `sign_transfer` hits:

```rust
// near/omni-bridge/src/lib.rs L462-469
let token_address = self
    .get_token_address(
        transfer_message.get_destination_chain(),
        self.get_token_id(&transfer_message.token),
    )
    .unwrap_or_else(|| {
        env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
    });
```

`get_token_address` (L1360-1366) returns `None` for any `(chain_kind, token)` pair not in `token_id_to_address`, causing `sign_transfer` to always panic. The transfer is permanently stuck.

The `ChainKind` enum has 13 variants (near/omni-types/src/lib.rs L53-83), and `OmniAddress` is parsed directly from a user-supplied string (near/omni-types/src/lib.rs L392-411), making any chain prefix reachable by any user. A token registered only on `Eth` has no entry for `(Fogo, token_id)`, `(HyperEvm, token_id)`, etc.

The only recovery path for native tokens is the DAO-privileged `transfer_token_as_dao` (L1511-1530). For deployed tokens that have been burned, there is no recovery path at all.

## Impact Explanation

**Deployed (bridged) tokens**: `burn_tokens_if_needed` is called unconditionally for any token in `deployed_tokens`/`deployed_tokens_v2`. The tokens are permanently destroyed with no on-chain recovery mechanism. This is a direct, irreversible loss of bridged funds matching the critical impact class: *permanent freezing or loss of bridged funds*.

**Native NEAR tokens**: Tokens are transferred to the bridge contract via `ft_transfer_call` and held there indefinitely. Without DAO intervention via `transfer_token_as_dao`, they are permanently frozen. This also matches the critical impact class.

## Likelihood Explanation

Any unprivileged token holder can trigger this by calling `ft_transfer_call` on any deployed token with a recipient address on a chain where the token is not registered (e.g., `fogo:BXss9YNCX2p6VPf2Em54pHXkXnC2FPBeZgbB9fY1cuBR`). The `OmniAddress` type is parsed from a user-supplied string, so no special access or privileges are required. The `ChainKind` enum includes newer chains (`Fogo`, `HyperEvm`, `Abs`, `Strk`) that may not have all tokens registered. This is directly and repeatably exploitable by any user, intentionally or accidentally.

## Recommendation

Add a validation in `init_transfer` (before any burn/lock operations and before storage deduction) that checks whether the token has a registered address on the destination chain:

```rust
require!(
    self.get_token_address(
        init_transfer_msg.get_destination_chain(),
        token_id.clone(),
    ).is_some(),
    BridgeError::TokenNotFound.as_ref()
);
```

This must be placed before `init_transfer_internal` is called so that `ft_on_transfer` can return the full amount to refund the user, and before any burn or lock operations occur.

## Proof of Concept

1. Token `eth.wrapped-eth.near` is a deployed token registered only for `ChainKind::Eth` (entry exists in `token_id_to_address` for `(Eth, eth.wrapped-eth.near)` but not for `(Fogo, eth.wrapped-eth.near)`).
2. User calls `ft_transfer_call` on `eth.wrapped-eth.near`:
   ```json
   {
     "receiver_id": "omni-bridge.near",
     "amount": "1000000",
     "msg": "{\"InitTransfer\":{\"recipient\":\"fogo:BXss9YNCX2p6VPf2Em54pHXkXnC2FPBeZgbB9fY1cuBR\",\"fee\":\"0\",\"native_token_fee\":\"0\"}}"
   }
   ```
3. `init_transfer` passes both checks (destination != Near, fee=0 < amount=1000000).
4. `init_transfer_internal` is called:
   - `burn_tokens_if_needed("eth.wrapped-eth.near", 1000000)` → `is_deployed_token` returns `true` → detached `burn(1000000)` promise fires → tokens permanently destroyed.
   - `lock_tokens_if_needed(Fogo, "eth.wrapped-eth.near", 1000000)` → `get_token_origin_chain` returns `Eth` ≠ `Fogo` → calls `lock_tokens` → `locked_tokens.get(&(Fogo, "eth.wrapped-eth.near"))` returns `None` → returns `Unchanged` (no accounting update).
5. `InitTransferEvent` is emitted; `ft_on_transfer` returns `U128(0)` — no refund.
6. Any relayer calling `sign_transfer` on this transfer ID: `get_token_address(Fogo, "eth.wrapped-eth.near")` returns `None` → panics with `ERR_FAILED_TO_GET_TOKEN_ADDRESS`.
7. Tokens are permanently lost with no user-callable recovery path.

A local integration test can be written using the existing `near/omni-tests` framework: deploy the bridge, register a token only for `Eth`, call `ft_transfer_call` with a `Fogo` recipient, and assert that (a) the token balance is reduced, (b) `ft_on_transfer` returns `0`, and (c) `sign_transfer` panics.