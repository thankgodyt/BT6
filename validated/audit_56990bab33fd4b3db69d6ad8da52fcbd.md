Audit Report

## Title
Tokens Permanently Frozen When `init_transfer` Targets an Unconfigured Destination Chain — (File: `near/omni-bridge/src/lib.rs`)

## Summary

`init_transfer` (invoked via `ft_on_transfer`) performs no validation that the destination chain has a registered token address before irrevocably committing user tokens. Once `init_transfer_internal` executes and returns `U128(0)`, the tokens remain in the bridge contract and the `TransferMessage` is stored in `pending_transfers`. The only forward path — `sign_transfer` — unconditionally panics when `get_token_address` returns `None` for the destination chain, and no user-callable cancellation or refund function exists anywhere in the contract.

## Finding Description

**Single guard in `init_transfer`** (lines 531–534): only rejects `ChainKind::Near` as a destination; all other `ChainKind` variants are accepted regardless of whether the token or chain is operationally configured.

**`init_transfer_internal`** (lines 1829–1865) then:
1. Stores the `TransferMessage` via `add_transfer_message`.
2. Deducts storage balance; if that succeeds, proceeds to token commitment.
3. Calls `burn_tokens_if_needed` (burns bridge-deployed tokens) and `lock_tokens_if_needed` (increments the locked-token counter for native tokens — or silently returns `Unchanged` if the chain has no entry in `locked_tokens`).
4. Returns `U128(0)`, signalling to the NEP-141 callback that **zero tokens are refunded** — the full amount stays in the bridge contract.

**`sign_transfer`** (lines 462–469) is the only forward path. It calls:
```rust
self.get_token_address(destination_chain, token_id)
    .unwrap_or_else(|| env::panic_str(...FailedToGetTokenAddress...));
```
For an unconfigured chain this always panics, so `sign_transfer_callback` is never reached and the `TransferMessage` is never removed from `pending_transfers`.

**No recovery path exists**: searching the contract reveals no `cancel_transfer`, `refund_transfer`, or any public function that removes a pending transfer and returns tokens to the sender. `remove_transfer_message_without_refund` is internal and only called on storage-balance failure (before token commitment) or in the `else` branch when `transfer_message.token` is not `OmniAddress::Near`. `sign_transfer_callback` and `claim_fee_callback` are only reachable after a successful MPC signing or proof, respectively — both blocked by the panic above.

**`lock_tokens_if_needed` subtlety** (token_lock.rs lines 96–107): if `locked_tokens` has no entry for `(chain_kind, token_id)`, `lock_tokens` returns `LockAction::Unchanged` without updating any counter. The tokens are physically held by the bridge contract but are not tracked in the locked-token accounting, making them invisible to any accounting-based recovery.

## Impact Explanation

Permanent freezing of bridged funds — an explicitly listed Critical impact. Once `init_transfer_internal` returns `U128(0)`, the user's tokens are held by the bridge contract with no self-service recovery. For bridge-deployed tokens, `burn_tokens_if_needed` destroys them outright. For native tokens, they are held but untracked. In either case, `sign_transfer` will always panic for the unconfigured chain, leaving the `TransferMessage` in `pending_transfers` indefinitely. Even with DAO intervention (registering the token for the chain), if no bridge contract is deployed on the destination chain the MPC-signed payload can never be executed, making the loss permanent.

## Likelihood Explanation

Low in normal front-end usage (the UI only exposes configured chains), but the contract is directly callable by any NEAR account via `ft_transfer_call`. Any user interacting through the CLI, SDK, or a custom script can specify any `ChainKind` recipient. The `ChainKind` enum has 13 variants (Eth, Sol, Arb, Base, Bnb, Btc, Zcash, Pol, HyperEvm, Strk, Abs, Fogo, Near), all accepted by `OmniAddress` parsing, and the contract imposes no on-chain restriction on which ones may be used as a destination.

## Recommendation

Before committing tokens in `init_transfer_internal` (or at the top of `init_transfer`), validate that the token is registered for the destination chain:

```rust
require!(
    self.get_token_address(
        transfer_message.get_destination_chain(),
        self.get_token_id(&transfer_message.token),
    ).is_some(),
    BridgeError::FailedToGetTokenAddress.as_ref()
);
```

This causes `ft_on_transfer` to return the full token amount (refunding the user) instead of `U128(0)`, preventing any commitment when the destination is unconfigured.

## Proof of Concept

1. Token `foo.near` is registered for `ChainKind::Eth` but **not** for `ChainKind::Fogo`. No entry exists in `locked_tokens` for `(Fogo, foo.near)`.
2. User calls `ft_transfer_call` on `foo.near`:
   ```json
   {
     "receiver_id": "omni-bridge.near",
     "amount": "1000000",
     "msg": "{\"InitTransfer\":{\"recipient\":\"fogo:2xNweLHLqbS9YpP3UyaPrxKqgqoC6yPBFyuLxA8qtgr4\",\"fee\":\"0\",\"native_token_fee\":\"0\"}}"
   }
   ```
3. `init_transfer` passes the only guard (`get_chain() != Near`). [1](#0-0) 
4. `init_transfer_internal` stores the `TransferMessage`, calls `burn_tokens_if_needed` / `lock_tokens_if_needed`, and returns `U128(0)` — tokens stay in the bridge. [2](#0-1) 
5. `lock_tokens_if_needed` finds no entry for `(Fogo, foo.near)` in `locked_tokens` and returns `Unchanged` — tokens are untracked. [3](#0-2) 
6. Relayer calls `sign_transfer`. `get_token_address(Fogo, foo.near)` returns `None` → contract panics with `ERR_FAILED_TO_GET_TOKEN_ADDRESS`. [4](#0-3) 
7. `TransferMessage` remains in `pending_transfers`. User's 1,000,000 tokens are frozen with no recovery path.

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

**File:** near/omni-bridge/src/lib.rs (L1850-1864)
```rust
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
```

**File:** near/omni-bridge/src/token_lock.rs (L55-57)
```rust
        let Some(current_amount) = self.locked_tokens.get(&key) else {
            return LockAction::Unchanged;
        };
```
