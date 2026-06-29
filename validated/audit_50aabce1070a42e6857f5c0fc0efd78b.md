### Title
Missing `locked_tokens` Initialization in `deploy_token_internal` and `add_deployed_tokens` Causes Silent Escrow Mis-Accounting - (File: `near/omni-bridge/src/lib.rs`, `near/omni-bridge/src/token_lock.rs`)

---

### Summary

When tokens are registered via `deploy_token_internal` (the primary permissionless deployment path) or `add_deployed_tokens`, the `locked_tokens` map is never initialized for the new token. Because `lock_tokens` and `unlock_tokens` both silently return `LockAction::Unchanged` when the map key is absent, every subsequent lock and unlock call for these tokens is a no-op. The escrow accounting invariant is permanently broken for the entire lifetime of those tokens.

---

### Finding Description

The `locked_tokens` map (`LookupMap<(ChainKind, AccountId), u128>`) is the bridge's on-chain ledger of how many tokens are held in escrow on each foreign chain. Two internal helpers read it:

**`lock_tokens`** (`near/omni-bridge/src/token_lock.rs`, lines 54–56):
```rust
let Some(current_amount) = self.locked_tokens.get(&key) else {
    return LockAction::Unchanged;   // ← silent no-op when key absent
};
```

**`unlock_tokens`** (`near/omni-bridge/src/token_lock.rs`, lines 77–79):
```rust
let Some(available) = self.locked_tokens.get(&key) else {
    return LockAction::Unchanged;   // ← silent no-op; InsufficientLockedTokens check bypassed
};
```

`bind_token_callback` (`near/omni-bridge/src/lib.rs`, lines 1269–1280) correctly seeds the map entry to `0` immediately after registering the token:
```rust
require!(
    self.locked_tokens
        .insert(&(deploy_token.token_address.get_chain(), deploy_token.token.clone()), &0)
        .is_none(),
    TokenLockError::TokenAlreadyLocked.as_ref()
);
```

However, the two other registration paths never perform this initialization:

- **`deploy_token_internal`** (`near/omni-bridge/src/lib.rs`, lines 2413–2426): calls `add_token`, inserts into `deployed_tokens` and `deployed_tokens_v2`, but never touches `locked_tokens`.
- **`add_deployed_tokens`** (`near/omni-bridge/src/lib.rs`, lines 1542–1556): calls `add_token`, inserts into `deployed_tokens` and `deployed_tokens_v2`, but never touches `locked_tokens`.

`deploy_token_internal` is invoked by the public, pausable `deploy_token` function (callable by any user when the bridge is unpaused) and by the DAO-only `deploy_native_token`. `add_deployed_tokens` is DAO-only.

---

### Impact Explanation

For every token registered through `deploy_token_internal` or `add_deployed_tokens`:

1. **All `lock_tokens_if_needed` calls are silent no-ops.** When a user calls `ft_on_transfer` → `init_transfer_internal` → `lock_tokens_if_needed`, the function reaches `lock_tokens`, finds no map entry, and returns `LockAction::Unchanged`. The user's tokens are burned on NEAR, but the escrow counter is never incremented. The bridge permanently under-counts locked supply for that token on every destination chain.

2. **All `unlock_tokens_if_needed` calls are silent no-ops.** During `fin_transfer_callback` → `process_fin_transfer_to_near` → `unlock_tokens_if_needed`, the function reaches `unlock_tokens`, finds no map entry, and returns `LockAction::Unchanged`. The `require!(available >= amount, InsufficientLockedTokens)` guard is never reached, so the bridge cannot enforce that it only releases tokens it actually holds in escrow.

3. **Revert logic is broken.** `process_fin_transfer_to_near` stores the `LockAction` in `lock_actions` and calls `revert_lock_actions` on failure. Because the action is always `Unchanged`, a failed finalization cannot restore the escrow counter, leaving the accounting permanently inconsistent.

4. **`process_fin_transfer_to_other_chain`** (`near/omni-bridge/src/lib.rs`, lines 1997–2022) calls both `unlock_tokens_if_needed` and `lock_tokens_if_needed` for cross-chain re-routing; both are no-ops for affected tokens.

The net result is that the bridge's `locked_tokens` ledger is permanently zeroed for all tokens deployed through the permissionless `deploy_token` path, making the escrow accounting invariant unenforceable for those tokens.

---

### Likelihood Explanation

`deploy_token` is the standard, permissionless path for deploying any foreign-chain token onto NEAR. It is callable by any user who pays the required storage deposit. Every token deployed through this path (which is the majority of bridged tokens) is affected from the moment of deployment. No special conditions or timing windows are required; the broken state is established at token registration and persists indefinitely.

---

### Recommendation

In `deploy_token_internal`, after `add_token` succeeds, insert a zero entry into `locked_tokens` for the origin chain, mirroring `bind_token_callback`:

```rust
self.locked_tokens.insert(
    &(token_address.get_chain(), token_id.clone()),
    &0,
);
```

Apply the same fix in `add_deployed_tokens` for each token in the batch. This ensures `lock_tokens` and `unlock_tokens` always find an existing entry and correctly update the escrow counter.

---

### Proof of Concept

1. Any user calls `deploy_token` for a foreign-chain token (e.g., an EVM token). `deploy_token_internal` runs; `locked_tokens[(Eth, token_id)]` is never set.
2. The user calls `ft_on_transfer` with an `InitTransfer` message targeting Ethereum. `init_transfer_internal` (lib.rs:1853–1857) calls `lock_tokens_if_needed(Eth, token_id, amount)`. `lock_tokens` (token_lock.rs:55–56) finds no entry and returns `LockAction::Unchanged`. The user's NEAR tokens are burned; the escrow counter stays at `None`.
3. A relayer submits a valid proof and calls `fin_transfer`. `process_fin_transfer_to_near` (lib.rs:1881–1885) calls `unlock_tokens_if_needed(Eth, token_id, amount)`. `unlock_tokens` (token_lock.rs:78–79) finds no entry and returns `LockAction::Unchanged`. The `InsufficientLockedTokens` guard is never evaluated. Tokens are minted to the recipient.
4. `get_locked_tokens(Eth, token_id)` returns `None` throughout, confirming the escrow ledger was never updated despite real token movements occurring. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** near/omni-bridge/src/lib.rs (L1269-1280)
```rust
        require!(
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

**File:** near/omni-bridge/src/lib.rs (L1542-1556)
```rust
        for token_info in tokens {
            self.deployed_tokens.insert(&token_info.token_id);
            self.deployed_tokens_v2
                .insert(&token_info.token_id, &token_info.token_address.get_chain());
            self.add_token(
                &token_info.token_id,
                &token_info.token_address,
                token_info.decimals,
                token_info.decimals,
            );
            ext_token::ext(token_info.token_id.clone())
                .with_static_gas(STORAGE_DEPOSIT_GAS)
                .with_attached_deposit(NEP141_DEPOSIT)
                .storage_deposit(&env::current_account_id(), Some(true))
                .detach();
```

**File:** near/omni-bridge/src/lib.rs (L1850-1857)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
```

**File:** near/omni-bridge/src/lib.rs (L1881-1885)
```rust
        let lock_actions = vec![self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        )];
```

**File:** near/omni-bridge/src/lib.rs (L2413-2426)
```rust
        let storage_usage = env::storage_usage();
        self.add_token(
            &token_id,
            token_address,
            metadata.decimals,
            metadata.decimals,
        );

        require!(
            self.deployed_tokens.insert(&token_id),
            BridgeError::TokenExists.as_ref()
        );
        self.deployed_tokens_v2
            .insert(&token_id, &token_address.get_chain());
```
