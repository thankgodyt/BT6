Audit Report

## Title
Uninitialized `locked_tokens` Entry Silently Skips Balance Accounting, Enabling Permanent Freezing of Bridged Funds - (File: near/omni-bridge/src/token_lock.rs)

## Summary
`lock_tokens` and `unlock_tokens` in `token_lock.rs` silently return `LockAction::Unchanged` when a `(chain_kind, token_id)` key is absent from `locked_tokens`. Because `locked_tokens` is only initialized to `0` during `bind_token_callback`, any transfer routed to a destination chain before that chain's entry is initialized bypasses accounting entirely. After `bind_token` is later called (initializing the entry to `0`), the bridge's recorded balance is permanently lower than the actual token supply on that chain, allowing an attacker to cause other users' funds to be permanently frozen.

## Finding Description

`lock_tokens` performs a lookup and silently no-ops on `None`:

```rust
// near/omni-bridge/src/token_lock.rs:54-57
let key = (chain_kind, token_id.clone());
let Some(current_amount) = self.locked_tokens.get(&key) else {
    return LockAction::Unchanged;   // silent skip, no error
};
```

`unlock_tokens` does the same:

```rust
// near/omni-bridge/src/token_lock.rs:77-80
let key = (chain_kind, token_id.clone());
let Some(available) = self.locked_tokens.get(&key) else {
    return LockAction::Unchanged;   // silent skip, no error
};
```

The only place `locked_tokens[(chain, token)]` is initialized is inside `bind_token_callback`:

```rust
// near/omni-bridge/src/lib.rs:1269-1280
require!(
    self.locked_tokens
        .insert(
            &(deploy_token.token_address.get_chain(), deploy_token.token.clone()),
            &0,
        )
        .is_none(),
    TokenLockError::TokenAlreadyLocked.as_ref()
);
```

`process_fin_transfer_to_other_chain` calls both `unlock_tokens_if_needed` and `lock_tokens_if_needed` with no guard checking whether the destination chain's entry is initialized:

```rust
// near/omni-bridge/src/lib.rs:1997-2022
self.unlock_tokens_if_needed(transfer_message.get_origin_chain(), &token, transfer_message.amount.0);
self.lock_tokens_if_needed(transfer_message.get_destination_chain(), &token, transfer_message.fee.fee.into());
// ...
self.lock_tokens_if_needed(transfer_message.get_destination_chain(), &token, transfer_message.amount_without_fee()...);
```

**Exploit flow:**

1. Token T is registered for Ethereum. `locked_tokens[(Base, T)]` does not yet exist (only `(Eth, T)` is initialized, and the origin-chain guard makes it irrelevant).
2. Attacker bridges 100 T from Ethereum → Base before `bind_token` for Base is called. `lock_tokens_if_needed(Base, T, 100)` → key absent → `Unchanged`. 100 T are minted on Base; bridge records nothing.
3. `bind_token` for Base is called → `locked_tokens[(Base, T)] = 0`.
4. Legitimate user bridges 100 T from Ethereum → Base. `lock_tokens_if_needed(Base, T, 100)` → `locked_tokens[(Base, T)] = 100`. 100 T minted on Base.
5. Attacker bridges their 100 T from Base → Ethereum. `unlock_tokens_if_needed(Base, T, 100)` → `locked_tokens[(Base, T)] = 0`. Attacker recovers 100 T on Ethereum.
6. Legitimate user attempts to bridge their 100 T from Base → Ethereum. `unlock_tokens_if_needed(Base, T, 100)` → **panics**: `InsufficientLockedTokens` (0 < 100). Legitimate user's 100 T are permanently frozen on Base.

The `require!` at `token_lock.rs:81-84` enforces `available >= amount` only when the key exists — after `bind_token` initializes to `0`, any subsequent unlock of a pre-`bind_token` transfer will panic.

## Impact Explanation

This is a concrete instance of **permanent freezing of bridged funds** and **escrow mis-accounting**, both of which are listed Critical impacts. The bridge's `locked_tokens` invariant is broken: 100 T exist on Base but the bridge records 0. The legitimate user's funds are irrecoverably frozen with no on-chain recovery path (the `set_locked_tokens` admin function exists but requires DAO/TokenLockController intervention and is not a protocol-level safeguard). The attacker recovers their own tokens at zero net cost, permanently freezing an equal amount of another user's tokens.

## Likelihood Explanation

- Any unprivileged user can trigger `fin_transfer` (via cross-chain message finalization) routing to a destination chain before `bind_token` is called for that chain on NEAR.
- The operational window is realistic: a token factory on Base deploys the token contract, but `bind_token` on NEAR is a separate subsequent transaction. During this gap, transfers can be processed.
- No admin compromise or special privilege is required; a standard bridge user with tokens on the origin chain is sufficient.
- The attack is repeatable for every new chain expansion of any token.

## Recommendation

In `lock_tokens` and `unlock_tokens`, treat a missing `locked_tokens` entry as an error rather than a silent no-op:

```rust
fn lock_tokens(&mut self, chain_kind: ChainKind, token_id: &AccountId, amount: u128) -> LockAction {
    let key = (chain_kind, token_id.clone());
    let current_amount = self.locked_tokens.get(&key)
        .near_expect(TokenLockError::TokenNotRegisteredForChain);
    // ...
}
```

Alternatively, add an explicit pre-check in `init_transfer_internal` and `process_fin_transfer_to_other_chain` asserting that `locked_tokens[(destination_chain, token)]` is initialized before proceeding. The `set_locked_tokens` admin escape hatch should be retained for emergency correction but must not be the primary safeguard.

## Proof of Concept

**Minimal contract call sequence (private testnet):**

1. Deploy the NEAR omni-bridge contract and register token T for Ethereum (`bind_token` for Eth → `locked_tokens[(Eth, T)] = 0`).
2. Do **not** call `bind_token` for Base yet.
3. Submit a `fin_transfer` message routing 100 T from Ethereum → Base (attacker-controlled recipient on Base). Observe: `lock_tokens_if_needed(Base, T, 100)` returns `Unchanged`; `locked_tokens` has no `(Base, T)` entry. Tokens are minted on Base.
4. Call `bind_token` for Base → `locked_tokens[(Base, T)] = 0`.
5. Submit a legitimate `fin_transfer` of 100 T from Ethereum → Base. Observe: `locked_tokens[(Base, T)] = 100`.
6. Submit attacker's `fin_transfer` (Base → Eth, 100 T). Observe: `locked_tokens[(Base, T)] = 0`.
7. Submit legitimate user's `fin_transfer` (Base → Eth, 100 T). Observe: **panic** `InsufficientLockedTokens`. Legitimate user's 100 T are permanently frozen.

**Unit test:** Write a test in `token_lock.rs` that calls `lock_tokens` with a key not present in `locked_tokens`, then inserts the key at `0`, then calls `unlock_tokens` with the same amount — confirm it panics with `InsufficientLockedTokens`.