Audit Report

## Title
`migrate_deployed_token` Orphans `locked_tokens` Entries, Permanently Breaking Escrow Accounting for the New Token ID — (File: near/omni-bridge/src/lib.rs)

## Summary

`migrate_deployed_token` updates five token-ID data structures but never touches `locked_tokens`, the bridge's escrow ledger. After migration, all `(chain_kind, old_token)` entries are permanently orphaned and unreachable, while `(chain_kind, new_token)` entries never exist. Because `lock_tokens` and `unlock_tokens` both silently return `LockAction::Unchanged` when a key is absent, every subsequent lock and unlock call for the migrated token is a no-op, the `require!(available >= amount)` safety invariant is permanently bypassed for `new_token`, and the bridge's view of outstanding cross-chain supply is permanently corrupted.

## Finding Description

`migrate_deployed_token` (lines 1604–1664, `near/omni-bridge/src/lib.rs`) updates `deployed_tokens`, `deployed_tokens_v2`, `token_id_to_address`, `token_address_to_id`, and `migrated_tokens`, but makes no changes to `locked_tokens : LookupMap<(ChainKind, AccountId), u128>`. [1](#0-0) 

`lock_tokens` (token_lock.rs:55–56) returns `LockAction::Unchanged` when the key is absent: [2](#0-1) 

`unlock_tokens` (token_lock.rs:78–83) also returns `LockAction::Unchanged` when the key is absent, skipping the `require!(available >= amount)` guard entirely: [3](#0-2) 

`lock_tokens_if_needed` and `unlock_tokens_if_needed` guard on `get_token_origin_chain(token_id) == chain_kind`. After migration, `deployed_tokens_v2` correctly maps `new_token → origin_chain`, so for any cross-chain transfer where `chain_kind != origin_chain`, this guard does not short-circuit — the call proceeds to `lock_tokens`/`unlock_tokens`, which silently no-ops because `(chain_kind, new_token)` was never inserted: [4](#0-3) 

The `set_locked_tokens` admin function (token_lock.rs:38–44) exists and could theoretically be used to repair the state post-migration, but it is not called atomically within `migrate_deployed_token` and there is no documented requirement to call it: [5](#0-4) 

**Exploit flow:**
1. Token `old_token` is deployed; `locked_tokens[(Sol, old_token)] = 500_000`.
2. DAO calls `migrate_deployed_token(Eth, old_token, new_token)`.
3. `locked_tokens[(Sol, old_token)]` is permanently orphaned; `locked_tokens[(Sol, new_token)]` does not exist.
4. User sends `new_token` to bridge to Solana. `lock_tokens_if_needed(Sol, new_token, 1_000)` reaches `lock_tokens`, finds no key, returns `Unchanged`. No lock is recorded.
5. Relayer submits a valid Solana proof and calls `fin_transfer`. `unlock_tokens_if_needed(Sol, new_token, 1_000)` reaches `unlock_tokens`, finds no key, returns `Unchanged`. The `require!(available >= amount)` check is never executed. Tokens are released on NEAR with zero escrow backing.
6. The bridge's escrow ledger permanently misrepresents the outstanding cross-chain supply for both `old_token` (inflated by the orphaned amount) and `new_token` (no tracking at all).

## Impact Explanation

This is a concrete escrow mis-accounting issue matching the allowed impact class: "Balance manipulation, escrow mis-accounting… that changes user or protocol balances." The `locked_tokens` ledger is the bridge's primary invariant ensuring that tokens released on NEAR are backed by tokens locked cross-chain. After migration, this invariant is permanently disabled for `new_token`: the `require!(available >= amount)` guard in `unlock_tokens` is never reached, meaning the bridge can release `new_token` on NEAR without any escrow backing recorded in its own state. The orphaned `old_token` entries permanently inflate the bridge's reported outstanding supply on each foreign chain.

## Likelihood Explanation

Token migration is an explicitly supported, production-ready feature evidenced by the `migrated_tokens` map, `swap_migrated_token`, and `MigrateTokenEvent`. Any DAO-initiated call to `migrate_deployed_token` for a token with non-zero `locked_tokens` entries triggers the accounting corruption. No attacker action is required — normal bridge usage after migration (by any user or relayer) exercises the broken code paths. The DAO performing a migration is a routine operational action, not an attack.

## Recommendation

Inside `migrate_deployed_token`, after updating the token-ID mappings, iterate over all `ChainKind` variants and migrate every existing `locked_tokens` entry atomically:

```rust
for chain_kind in ChainKind::all() {
    let old_key = (chain_kind, old_token.clone());
    if let Some(amount) = self.locked_tokens.remove(&old_key) {
        self.locked_tokens.insert(&(chain_kind, new_token.clone()), &amount);
    }
}
```

Alternatively, enforce that `set_locked_tokens` is called as a mandatory, atomic step of any token migration by adding an assertion inside `migrate_deployed_token` that no `locked_tokens` entries exist for `old_token` before proceeding, and documenting the required call sequence.

## Proof of Concept

**Unit/integration test plan:**

1. Initialize the bridge contract with `old_token` deployed and `locked_tokens[(Sol, old_token)] = 500_000`.
2. Call `migrate_deployed_token(Eth, old_token, new_token)` as DAO.
3. Assert `get_locked_tokens(Sol, old_token)` still returns `Some(500_000)` (orphaned).
4. Assert `get_locked_tokens(Sol, new_token)` returns `None`.
5. Call `lock_tokens_if_needed(Sol, new_token, 1_000)` and assert it returns `LockAction::Unchanged`.
6. Call `unlock_tokens_if_needed(Sol, new_token, 1_000)` and assert it returns `LockAction::Unchanged` without panicking (demonstrating the `require!` guard is bypassed).
7. Confirm `get_locked_tokens(Sol, new_token)` still returns `None` after both calls.

This sequence is directly reproducible in the existing test harness at `near/omni-bridge/src/tests/lib_test.rs` using the `set_locked_tokens` setup helper already present in that file. [6](#0-5)

### Citations

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

**File:** near/omni-bridge/src/token_lock.rs (L38-44)
```rust
    #[access_control_any(roles(Role::DAO, Role::TokenLockController))]
    pub fn set_locked_tokens(&mut self, args: Vec<SetLockedTokenArgs>) {
        for arg in args {
            self.locked_tokens
                .insert(&(arg.chain_kind, arg.token_id), &arg.amount.0);
        }
    }
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

**File:** near/omni-bridge/src/token_lock.rs (L96-120)
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
