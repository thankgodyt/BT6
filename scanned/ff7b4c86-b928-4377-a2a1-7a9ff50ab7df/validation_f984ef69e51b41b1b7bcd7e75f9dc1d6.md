### Title
`migrate_deployed_token()` Does Not Update `locked_tokens` — (`near/omni-bridge/src/lib.rs`)

### Summary

`migrate_deployed_token()` updates five token-identity maps when replacing `old_token` with `new_token`, but it never migrates the `locked_tokens` entries that are keyed by `(ChainKind, AccountId)`. After migration the bridge's escrow-accounting invariant is permanently broken for the migrated token: all lock/unlock operations on `new_token` silently no-op, and the `InsufficientLockedTokens` safety check is permanently bypassed.

### Finding Description

`migrate_deployed_token` updates the following state:

- `deployed_tokens` (remove old / insert new)
- `deployed_tokens_v2` (remove old / insert new)
- `token_id_to_address` (remove old key / insert new key)
- `token_address_to_id` (overwrite to new token)
- `migrated_tokens` (record old→new) [1](#0-0) 

It does **not** touch `locked_tokens`, which is a separate `LookupMap<(ChainKind, AccountId), u128>` keyed by the NEAR `AccountId` of the token. [2](#0-1) 

`locked_tokens` is initialised for every token at `bind_token_callback` time: [3](#0-2) 

After `migrate_deployed_token(origin_chain, old_token, new_token)`:

- `locked_tokens[(chain, old_token)]` still exists with its last value — stale, never decremented again.
- `locked_tokens[(chain, new_token)]` does **not** exist.

Every subsequent lock/unlock call for `new_token` hits the early-return branch in `lock_tokens` / `unlock_tokens`:

```rust
let Some(current_amount) = self.locked_tokens.get(&key) else {
    return LockAction::Unchanged;   // key absent → silent no-op
};
``` [4](#0-3) [5](#0-4) 

This means `lock_tokens_if_needed` and `unlock_tokens_if_needed` — called from every `fin_transfer` and `init_transfer` path — silently return `Unchanged` for `new_token` on every chain. [6](#0-5) [7](#0-6) 

The `InsufficientLockedTokens` guard inside `unlock_tokens` is therefore permanently unreachable for `new_token`: [8](#0-7) 

### Impact Explanation

The `locked_tokens` map is the bridge's on-chain escrow ledger. It enforces that the total amount minted on NEAR for a given `(chain, token)` pair never exceeds the total amount locked on the source chain. After migration:

1. **Stale orphaned entries** — `locked_tokens[(chain, old_token)]` retains its last value forever. No future operation will decrement it, so the bridge's aggregate accounting is permanently wrong.
2. **Safety-check bypass** — `locked_tokens[(chain, new_token)]` is absent. Every `fin_transfer` for `new_token` from any chain succeeds without the `InsufficientLockedTokens` guard. If the prover is ever compromised or a proof-parsing flaw exists, the bridge will mint `new_token` without any secondary escrow check.
3. **`init_transfer` lock silently skipped** — when a user bridges `new_token` from NEAR to another chain, `lock_tokens_if_needed` returns `Unchanged`, so the destination-chain locked balance is never incremented. Subsequent `fin_transfer` calls from that chain will also silently skip the unlock, making the accounting permanently diverge from reality.

This is escrow mis-accounting that changes protocol balances and removes a critical safety invariant.

### Likelihood Explanation

`migrate_deployed_token` is a DAO-callable function that exists precisely to be used in production token-upgrade scenarios. It is not a hypothetical path. Any invocation — even a well-intentioned one — silently corrupts `locked_tokens` for the migrated token. No attacker action is required beyond waiting for the DAO to perform a routine migration.

### Recommendation

Inside `migrate_deployed_token`, after updating the identity maps, migrate every `locked_tokens` entry from `old_token` to `new_token`. Concretely, iterate over all `ChainKind` variants that have a `locked_tokens` entry for `old_token`, remove the old key, and insert the same value under the new key. At minimum, migrate the entry for `origin_chain` (which is already a parameter) and any other chains that may have been registered via `bind_token_callback` or `set_locked_tokens`.

```rust
// Example fix (inside migrate_deployed_token, after existing map updates):
for chain in all_chain_kinds() {
    if let Some(amount) = self.locked_tokens.remove(&(chain, old_token.clone())) {
        self.locked_tokens.insert(&(chain, new_token.clone()), &amount);
    }
}
```

Alternatively, add a dedicated `migrate_locked_tokens` step that the DAO must call alongside `migrate_deployed_token`, and document it as a required post-migration action.

### Proof of Concept

1. Token `eth-token.near` is deployed via `bind_token`. `locked_tokens[(Eth, eth-token.near)] = 5000` after several transfers.
2. DAO calls `migrate_deployed_token(ChainKind::Eth, "eth-token.near", "eth-token-v2.near")`.
3. `locked_tokens` still contains `(Eth, eth-token.near) → 5000`; `(Eth, eth-token-v2.near)` does not exist.
4. A relayer calls `fin_transfer` for `eth-token-v2.near` from Eth with amount `10_000` (more than any real locked balance). `unlock_tokens_if_needed(Eth, &"eth-token-v2.near", 10_000)` looks up `(Eth, eth-token-v2.near)` → absent → returns `Unchanged`. The `InsufficientLockedTokens` panic is never reached. The bridge mints `10_000` tokens to the recipient.
5. The stale entry `(Eth, eth-token.near) → 5000` remains in `locked_tokens` forever, making the bridge's aggregate escrow accounting permanently incorrect. [9](#0-8) [10](#0-9) [11](#0-10)

### Citations

**File:** near/omni-bridge/src/lib.rs (L241-243)
```rust
    pub migrated_tokens: LookupMap<AccountId, AccountId>,
    pub locked_tokens: LookupMap<(ChainKind, AccountId), u128>,
}
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

**File:** near/omni-bridge/src/lib.rs (L1604-1664)
```rust
    #[access_control_any(roles(Role::DAO))]
    #[payable]
    pub fn migrate_deployed_token(
        &mut self,
        origin_chain: ChainKind,
        old_token: AccountId,
        new_token: AccountId,
    ) {
        require!(
            env::attached_deposit() >= NEP141_DEPOSIT,
            BridgeError::NotEnoughAttachedDeposit.as_ref()
        );

        require!(
            self.deployed_tokens.remove(&old_token),
            BridgeError::OldTokenNotDeployed.as_ref(),
        );
        require!(
            self.deployed_tokens.insert(&new_token),
            BridgeError::TokenExists.as_ref()
        );
        self.deployed_tokens_v2.remove(&old_token);
        self.deployed_tokens_v2.insert(&new_token, &origin_chain);

        let origin_address = self
            .token_id_to_address
            .remove(&(origin_chain, old_token.clone()))
            .near_expect(BridgeError::FailedToGetTokenAddress);

        require!(
            self.token_id_to_address
                .insert(&(origin_chain, new_token.clone()), &origin_address)
                .is_none(),
            BridgeError::TokenExists.as_ref()
        );

        self.token_address_to_id
            .insert(&origin_address, &new_token)
            .near_expect(BridgeError::ExpectedToOverwriteTokenAddress);

        require!(
            self.migrated_tokens
                .insert(&old_token, &new_token)
                .is_none(),
            BridgeError::TokenAlreadyMigrated.as_ref()
        );

        ext_token::ext(new_token.clone())
            .with_static_gas(STORAGE_DEPOSIT_GAS)
            .with_attached_deposit(NEP141_DEPOSIT)
            .storage_deposit(&env::current_account_id(), Some(true))
            .detach();

        env::log_str(
            &OmniBridgeEvent::MigrateTokenEvent {
                old_token_id: old_token,
                new_token_id: new_token,
            }
            .to_log_string(),
        );
    }
```

**File:** near/omni-bridge/src/lib.rs (L1997-2005)
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
```

**File:** near/omni-bridge/src/token_lock.rs (L54-57)
```rust
        let key = (chain_kind, token_id.clone());
        let Some(current_amount) = self.locked_tokens.get(&key) else {
            return LockAction::Unchanged;
        };
```

**File:** near/omni-bridge/src/token_lock.rs (L71-94)
```rust
    fn unlock_tokens(
        &mut self,
        chain_kind: ChainKind,
        token_id: &AccountId,
        amount: u128,
    ) -> LockAction {
        let key = (chain_kind, token_id.clone());
        let Some(available) = self.locked_tokens.get(&key) else {
            return LockAction::Unchanged;
        };
        require!(
            available >= amount,
            TokenLockError::InsufficientLockedTokens.as_ref()
        );

        let remaining = available - amount;
        self.locked_tokens.insert(&key, &remaining);

        LockAction::Unlocked {
            chain_kind,
            token_id: token_id.clone(),
            amount,
        }
    }
```

**File:** near/omni-bridge/src/token_lock.rs (L96-107)
```rust
    pub(crate) fn lock_tokens_if_needed(
        &mut self,
        chain_kind: ChainKind,
        token_id: &AccountId,
        amount: u128,
    ) -> LockAction {
        if self.get_token_origin_chain(token_id) == chain_kind || amount == 0 {
            return LockAction::Unchanged;
        }

        self.lock_tokens(chain_kind, token_id, amount)
    }
```

**File:** near/omni-bridge/src/token_lock.rs (L109-120)
```rust
    pub(crate) fn unlock_tokens_if_needed(
        &mut self,
        chain_kind: ChainKind,
        token_id: &AccountId,
        amount: u128,
    ) -> LockAction {
        if self.get_token_origin_chain(token_id) == chain_kind || amount == 0 {
            return LockAction::Unchanged;
        }

        self.unlock_tokens(chain_kind, token_id, amount)
    }
```
