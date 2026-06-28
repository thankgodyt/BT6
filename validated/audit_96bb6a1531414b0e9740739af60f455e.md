### Title
`migrate_deployed_token` Orphans `locked_tokens` Accounting, Breaking Escrow Invariant for Migrated Token - (File: `near/omni-bridge/src/lib.rs`)

### Summary

`migrate_deployed_token` is the NEAR Omni Bridge analog of `InsuranceFund#syncDeps()`. When the DAO migrates a deployed token from `old_token` to `new_token`, it updates all token registry mappings but silently omits migrating the `locked_tokens` map. After migration, the locked-token accounting for `new_token` is permanently broken: every subsequent `lock_tokens_if_needed` and `unlock_tokens_if_needed` call for `new_token` silently returns `LockAction::Unchanged`, bypassing the escrow invariant entirely.

### Finding Description

`migrate_deployed_token` (DAO-only) updates six data structures: [1](#0-0) 

It migrates `deployed_tokens`, `deployed_tokens_v2`, `token_id_to_address`, `token_address_to_id`, and `migrated_tokens`. It does **not** touch `locked_tokens`.

The `locked_tokens` map is keyed by `(ChainKind, AccountId)` where `AccountId` is the NEAR token ID: [2](#0-1) 

After migration:
- `locked_tokens[(chain, old_token)]` retains its accumulated balance but is permanently orphaned — no future code path decrements it.
- `locked_tokens[(chain, new_token)]` does not exist.

Both `lock_tokens` and `unlock_tokens` guard on key existence with an early return: [3](#0-2) [4](#0-3) 

When the key is absent, both functions return `LockAction::Unchanged` — silently skipping the operation with no error. After migration, every call to `lock_tokens_if_needed` or `unlock_tokens_if_needed` for `new_token` takes this path.

### Impact Explanation

The `locked_tokens` invariant is the NEAR-side escrow guard that ensures the bridge never releases more tokens than are actually locked on the foreign chain. After `migrate_deployed_token`:

1. **`fin_transfer` (EVM → NEAR)**: `unlock_tokens_if_needed(Eth, new_token, amount)` returns `Unchanged`. The bridge mints `new_token` to the recipient with no check that a corresponding lock exists on EVM. The `locked_tokens[(Eth, old_token)]` balance is never decremented, permanently inflating the orphaned counter. [5](#0-4) 

2. **`init_transfer` (NEAR → EVM)**: `lock_tokens_if_needed(Eth, new_token, amount)` returns `Unchanged`. The bridge records no lock for the outbound transfer, so the invariant that "locked tokens ≥ outstanding outbound transfers" is never enforced for `new_token`. [6](#0-5) 

3. **Rollback is also broken**: `revert_lock_actions` operates on the `LockAction` returned by the lock/unlock calls. Since all actions return `Unchanged`, rollback on failure does nothing for `new_token`. [7](#0-6) 

The net result is permanent escrow mis-accounting: the bridge loses the ability to enforce that NEAR-side releases of `new_token` are backed by EVM-side locks, and the orphaned `old_token` counter can never be reconciled.

### Likelihood Explanation

The DAO legitimately calls `migrate_deployed_token` as part of a token upgrade (e.g., migrating from a legacy token contract to a new one). This is an expected operational action, not an attack. The bug fires on every such migration. Any token migration after the bridge has accumulated locked-token balances will trigger the accounting corruption. The `swap_migrated_token` path for user token swaps does not repair the `locked_tokens` state.

### Recommendation

`migrate_deployed_token` must migrate the `locked_tokens` entry for every chain on which the token is tracked. Before removing `old_token` from the registry, enumerate all `(chain, old_token)` entries in `locked_tokens`, remove them, and insert equivalent entries under `(chain, new_token)`. A balance-conservation check analogous to the recommended fix in the original report should be added:

```rust
// Before migration:
let old_locked = self.locked_tokens.get(&(origin_chain, old_token.clone())).unwrap_or(0);
// After updating all other mappings:
self.locked_tokens.remove(&(origin_chain, old_token.clone()));
self.locked_tokens.insert(&(origin_chain, new_token.clone()), &old_locked);
// Invariant check: new accounting must equal old accounting
assert_eq!(
    self.locked_tokens.get(&(origin_chain, new_token.clone())),
    Some(old_locked)
);
```

### Proof of Concept

1. Bridge has `old_token` deployed; EVM users have locked 1 000 000 units. `locked_tokens[(Eth, old_token)] = 1_000_000`.
2. DAO calls `migrate_deployed_token(ChainKind::Eth, old_token, new_token)`.
   - `deployed_tokens`: `old_token` removed, `new_token` inserted.
   - `token_address_to_id[eth_address]` → `new_token`.
   - `locked_tokens[(Eth, old_token)] = 1_000_000` — **orphaned, never touched again**.
   - `locked_tokens[(Eth, new_token)]` — **does not exist**.
3. Relayer submits `fin_transfer` for a user's EVM-initiated transfer of 500 000 units.
   - `get_token_id(eth_address)` → `new_token`.
   - `unlock_tokens_if_needed(Eth, new_token, 500_000)` → key absent → `LockAction::Unchanged`.
   - Bridge mints 500 000 `new_token` to recipient. No locked-token decrement occurs.
4. Repeat step 3 for another 500 000 units. Same result.
5. `locked_tokens[(Eth, old_token)]` still reads `1_000_000` (stale). `locked_tokens[(Eth, new_token)]` still does not exist. The bridge has minted 1 000 000 `new_token` with zero accounting, and the escrow invariant is permanently unenforceable for `new_token`. [8](#0-7) [9](#0-8)

### Citations

**File:** near/omni-bridge/src/lib.rs (L242-242)
```rust
    pub locked_tokens: LookupMap<(ChainKind, AccountId), u128>,
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

**File:** near/omni-bridge/src/lib.rs (L1853-1857)
```rust
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

**File:** near/omni-bridge/src/token_lock.rs (L47-94)
```rust
impl Contract {
    fn lock_tokens(
        &mut self,
        chain_kind: ChainKind,
        token_id: &AccountId,
        amount: u128,
    ) -> LockAction {
        let key = (chain_kind, token_id.clone());
        let Some(current_amount) = self.locked_tokens.get(&key) else {
            return LockAction::Unchanged;
        };
        let new_amount = current_amount
            .checked_add(amount)
            .near_expect(TokenLockError::LockedTokensOverflow);

        self.locked_tokens.insert(&key, &new_amount);

        LockAction::Locked {
            chain_kind,
            token_id: token_id.clone(),
            amount,
        }
    }

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

**File:** near/omni-bridge/src/token_lock.rs (L122-142)
```rust
    pub fn revert_lock_actions(&mut self, lock_actions: &[LockAction]) {
        for lock_action in lock_actions {
            match lock_action {
                LockAction::Locked {
                    chain_kind,
                    token_id,
                    amount,
                } => {
                    self.unlock_tokens(*chain_kind, token_id, *amount);
                }
                LockAction::Unlocked {
                    chain_kind,
                    token_id,
                    amount,
                } => {
                    self.lock_tokens(*chain_kind, token_id, *amount);
                }
                LockAction::Unchanged => {}
            }
        }
    }
```
