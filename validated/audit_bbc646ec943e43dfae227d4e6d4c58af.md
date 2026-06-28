### Title
Uninitialized `locked_tokens` Entry Silently Skips Balance Accounting, Enabling Permanent Freezing of Bridged Funds - (File: near/omni-bridge/src/token_lock.rs)

---

### Summary

Both `lock_tokens` and `unlock_tokens` in `token_lock.rs` silently return `LockAction::Unchanged` when the `(chain_kind, token_id)` key is absent from the `locked_tokens` map. Because `locked_tokens` is only initialized to `0` during `bind_token_callback`, any transfer routed to a chain before that chain's token entry is initialized bypasses accounting entirely. After `bind_token` is later called (initializing the entry to `0`), the bridge's recorded balance is permanently lower than the actual token supply on that chain, allowing an attacker to cause other users' funds to be permanently frozen.

---

### Finding Description

`lock_tokens` (the inner function called by `lock_tokens_if_needed`) performs a `may_load`-equivalent lookup and silently no-ops on `None`:

```rust
// near/omni-bridge/src/token_lock.rs:54-57
let Some(current_amount) = self.locked_tokens.get(&key) else {
    return LockAction::Unchanged;   // ← silent skip, no error
};
```

`unlock_tokens` does the same:

```rust
// near/omni-bridge/src/token_lock.rs:77-80
let Some(available) = self.locked_tokens.get(&key) else {
    return LockAction::Unchanged;   // ← silent skip, no error
};
```

The only place `locked_tokens[(chain, token)]` is initialized is inside `bind_token_callback`:

```rust
// near/omni-bridge/src/lib.rs:1270-1280
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

Neither `init_transfer_internal` nor `process_fin_transfer_to_other_chain` checks whether the destination chain's entry is initialized before calling `lock_tokens_if_needed`:

```rust
// near/omni-bridge/src/lib.rs:1853-1857
self.lock_tokens_if_needed(
    transfer_message.get_destination_chain(),
    &token_id,
    transfer_message.amount.0,
);
```

```rust
// near/omni-bridge/src/lib.rs:2002-2022
self.lock_tokens_if_needed(
    transfer_message.get_destination_chain(),
    &token,
    transfer_message.fee.fee.into(),
);
// ...
self.lock_tokens_if_needed(
    transfer_message.get_destination_chain(),
    &token,
    transfer_message.amount_without_fee()...,
);
```

---

### Impact Explanation

For a foreign-origin token T (e.g., Ethereum-origin):

- `get_token_origin_chain(T) == Eth`, so `lock_tokens_if_needed(Eth, …)` always returns `Unchanged` (origin-chain guard). The only meaningful accounting is on non-origin chains (e.g., Base, Arbitrum).
- `locked_tokens[(Base, T)]` is only initialized when `bind_token` is called for Base.

**Permanent freezing of funds:**

1. Token T is registered for Ethereum. `locked_tokens[(Base, T)]` does not yet exist.
2. Attacker (or any user) bridges 100 T from Ethereum → Base before `bind_token` for Base is called.
   - `lock_tokens_if_needed(Base, T, 100)` → silently skipped. 100 T are minted on Base. Bridge records nothing.
3. `bind_token` for Base is called → `locked_tokens[(Base, T)] = 0`.
4. Legitimate user bridges 100 T from Ethereum → Base.
   - `lock_tokens_if_needed(Base, T, 100)` → `locked_tokens[(Base, T)] = 100`. 100 T minted on Base.
5. Attacker bridges their 100 T from Base → Ethereum.
   - `unlock_tokens_if_needed(Base, T, 100)` → `locked_tokens[(Base, T)] = 0`. Attacker receives 100 T on Ethereum.
6. Legitimate user attempts to bridge their 100 T from Base → Ethereum.
   - `unlock_tokens_if_needed(Base, T, 100)` → **panics**: `InsufficientLockedTokens` (`0 < 100`).
   - Legitimate user's 100 T are **permanently frozen** on Base.

The attacker recovers their own tokens at the cost of permanently freezing an equal amount of another user's tokens. The bridge's `locked_tokens` invariant is broken: 100 T exist on Base but the bridge records 0.

---

### Likelihood Explanation

- Any unprivileged user can call `init_transfer` (via `ft_transfer_call`) or trigger `fin_transfer` routing to a destination chain before `bind_token` is called for that chain.
- There is no guard in `init_transfer` or `fin_transfer` that checks whether `locked_tokens[(destination_chain, token)]` is initialized.
- The window exists whenever a token is deployed on a foreign chain but `bind_token` on NEAR has not yet been called — a realistic operational gap, especially during token expansion to new chains.
- No admin compromise or special privilege is required; a standard bridge user with tokens is sufficient.

---

### Recommendation

In `lock_tokens` and `unlock_tokens`, treat a missing `locked_tokens` entry as an error rather than a silent no-op. Revert the transaction if the `(chain_kind, token_id)` key is absent:

```rust
fn lock_tokens(...) -> LockAction {
    let key = (chain_kind, token_id.clone());
    let current_amount = self.locked_tokens.get(&key)
        .near_expect(TokenLockError::TokenNotRegisteredForChain);
    // ...
}
```

Alternatively, add an explicit pre-check in `init_transfer_internal` and `process_fin_transfer_to_other_chain` that asserts `locked_tokens[(destination_chain, token)]` is initialized before proceeding with the transfer.

---

### Proof of Concept

Root cause — silent no-op on uninitialized key: [1](#0-0) [2](#0-1) 

Initialization only happens in `bind_token_callback`: [3](#0-2) 

`init_transfer_internal` calls `lock_tokens_if_needed` with no initialization guard: [4](#0-3) 

`process_fin_transfer_to_other_chain` calls both lock and unlock with no initialization guard: [5](#0-4) 

`unlock_tokens` enforces `available >= amount` only when the key exists — after `bind_token` initializes to `0`, any subsequent unlock of a pre-`bind_token` transfer will panic: [6](#0-5)

### Citations

**File:** near/omni-bridge/src/token_lock.rs (L54-57)
```rust
        let key = (chain_kind, token_id.clone());
        let Some(current_amount) = self.locked_tokens.get(&key) else {
            return LockAction::Unchanged;
        };
```

**File:** near/omni-bridge/src/token_lock.rs (L77-80)
```rust
        let key = (chain_kind, token_id.clone());
        let Some(available) = self.locked_tokens.get(&key) else {
            return LockAction::Unchanged;
        };
```

**File:** near/omni-bridge/src/token_lock.rs (L81-84)
```rust
        require!(
            available >= amount,
            TokenLockError::InsufficientLockedTokens.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1270-1280)
```rust
            self.locked_tokens
                .insert(
                    &(
                        deploy_token.token_address.get_chain(),
                        deploy_token.token.clone(),
                    ),
                    &0,
                )
                .is_none(),
            TokenLockError::TokenAlreadyLocked.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1853-1857)
```rust
            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
```

**File:** near/omni-bridge/src/lib.rs (L1997-2022)
```rust
        self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        );
        self.lock_tokens_if_needed(
            transfer_message.get_destination_chain(),
            &token,
            transfer_message.fee.fee.into(),
        );

        let fast_transfer = FastTransfer::from_transfer(transfer_message.clone(), token.clone());
        let recipient = if let Some(status) = self.get_fast_transfer_status(&fast_transfer.id()) {
            require!(
                !status.finalised,
                BridgeError::FastTransferAlreadyFinalised.as_ref()
            );
            Some(status.relayer)
        } else {
            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token,
                transfer_message
                    .amount_without_fee()
                    .near_expect(BridgeError::InvalidFee),
            );
```
