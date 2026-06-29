### Title
Missing `locked_tokens` Initialization on Token Deployment Silently Bypasses Cross-Chain Escrow Accounting — (`File: near/omni-bridge/src/lib.rs`, `near/omni-bridge/src/token_lock.rs`)

---

### Summary

When a new token is deployed via `deploy_token_internal`, no entry is created in the `locked_tokens` map for any chain. Both `lock_tokens` and `unlock_tokens` silently return `LockAction::Unchanged` when the map entry is absent, completely bypassing the cross-chain escrow accounting invariant for every transfer involving that token.

---

### Finding Description

`deploy_token_internal` registers the token in `deployed_tokens` and `deployed_tokens_v2` but never seeds a `locked_tokens` entry: [1](#0-0) 

The `lock_tokens` function guards on the map entry's existence with an early-return: [2](#0-1) 

Identically, `unlock_tokens` silently skips when no entry is present: [3](#0-2) 

Both `lock_tokens_if_needed` and `unlock_tokens_if_needed` delegate to these functions: [4](#0-3) [5](#0-4) 

These helpers are called at every critical accounting point — `init_transfer_internal`, `process_fin_transfer_to_near`, `process_fin_transfer_to_other_chain`, `fast_fin_transfer_to_other_chain`, and `utxo_fin_transfer_to_other_chain`: [6](#0-5) [7](#0-6) [8](#0-7) 

The test environment itself reveals the required manual workaround — `set_locked_tokens` must be called explicitly after every token deployment, but `deploy_token_internal` never does this: [9](#0-8) 

The `_Relayers` storage key in the enum is a tombstone confirming that the relayer state was intentionally removed from the struct in the last migration, but `locked_tokens` was added without automatic initialization on deployment: [10](#0-9) 

---

### Impact Explanation

For every token deployed through the permissionless `deploy_token` path, the `locked_tokens` map has no entry for any `(ChainKind, token_id)` pair. As a result:

- `lock_tokens_if_needed` silently skips on every outbound transfer — the protocol never records how many tokens are in transit to each foreign chain.
- `unlock_tokens_if_needed` silently skips on every inbound transfer — the `ERR_INSUFFICIENT_LOCKED_TOKENS` guard (which is the protocol's last-resort check against minting more tokens than were locked on the source chain) is completely absent.

The cross-chain supply invariant — *locked_tokens(chain, token) = total tokens currently bridged to that chain* — is broken for the entire lifetime of the token unless the DAO manually calls `set_locked_tokens`. Any future `fin_transfer` proof accepted by the prover will mint tokens on NEAR without any accounting check, making the locked_tokens layer provide zero protection for these tokens. [11](#0-10) 

---

### Likelihood Explanation

The `deploy_token` entrypoint is permissionless — any user who pays the required storage deposit can trigger it: [12](#0-11) 

Every token deployed this way is permanently affected unless the DAO intervenes. The test harness demonstrates that the team is aware of the need to call `set_locked_tokens` post-deployment, but the production contract path does not enforce it. All existing and future deployed tokens are affected until the DAO manually seeds each `(chain, token)` pair.

---

### Recommendation

Initialize a `locked_tokens` entry with value `0` for the deploying chain inside `deploy_token_internal`, immediately after inserting into `deployed_tokens_v2`:

```rust
self.deployed_tokens_v2.insert(&token_id, &token_address.get_chain());
// Seed the locked_tokens entry so accounting is active from the first transfer
self.locked_tokens.insert(&(token_address.get_chain(), token_id.clone()), &0);
```

Additionally, consider initializing entries for all other supported chains at deploy time, or enforce that `set_locked_tokens` is called atomically as part of the deployment callback.

---

### Proof of Concept

1. Call `deploy_token` for a new EVM token (permissionless, any user with storage deposit).
2. Observe that `get_locked_tokens(ChainKind::Eth, token_id)` returns `None`.
3. Bridge the token from ETH → NEAR via `fin_transfer` with a valid proof.
4. Inside `process_fin_transfer_to_near`, `unlock_tokens_if_needed(Eth, token_id, amount)` returns `LockAction::Unchanged` — the `ERR_INSUFFICIENT_LOCKED_TOKENS` guard is never evaluated.
5. Tokens are minted on NEAR with zero escrow accounting.
6. Bridge the token from NEAR → Solana via `init_transfer`; `lock_tokens_if_needed(Sol, token_id, amount)` also returns `Unchanged` — the Solana-side locked balance is never incremented.
7. The protocol has no record of how many tokens are on Solana, making the locked_tokens invariant permanently broken for this token across all chains. [13](#0-12) [2](#0-1) [14](#0-13)

### Citations

**File:** near/omni-bridge/src/lib.rs (L108-111)
```rust
    LockedTokens,
    DeployedTokensV2,
    _Relayers,
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

**File:** near/omni-bridge/src/lib.rs (L1997-2006)
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
```

**File:** near/omni-bridge/src/lib.rs (L2397-2412)
```rust
    fn deploy_token_internal(
        &mut self,
        chain_kind: ChainKind,
        token_address: &OmniAddress,
        metadata: BasicMetadata,
        attached_deposit: NearToken,
    ) -> Promise {
        let deployer = self
            .token_deployer_accounts
            .get(&chain_kind)
            .unwrap_or_else(|| env::panic_str(BridgeError::DeployerNotSet.to_string().as_str()));
        let prefix = token_address.get_token_prefix();
        let token_id: AccountId = format!("{prefix}.{deployer}")
            .parse()
            .unwrap_or_else(|_| env::panic_str(BridgeError::ParseAccountId.to_string().as_str()));

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

**File:** near/omni-bridge/src/token_lock.rs (L54-57)
```rust
        let key = (chain_kind, token_id.clone());
        let Some(current_amount) = self.locked_tokens.get(&key) else {
            return LockAction::Unchanged;
        };
```

**File:** near/omni-bridge/src/token_lock.rs (L77-84)
```rust
        let key = (chain_kind, token_id.clone());
        let Some(available) = self.locked_tokens.get(&key) else {
            return LockAction::Unchanged;
        };
        require!(
            available >= amount,
            TokenLockError::InsufficientLockedTokens.as_ref()
        );
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

**File:** near/omni-tests/src/environment.rs (L95-112)
```rust
        if !self.deploy_old_version {
            set_locked_tokens(
                &bridge_contract,
                vec![
                    SetLockedTokenArgs {
                        chain_kind: ChainKind::Eth,
                        token_id: token_contract.id().clone(),
                        amount: U128(DEFAULT_LOCKED_TOKENS),
                    },
                    SetLockedTokenArgs {
                        chain_kind: ChainKind::Base,
                        token_id: token_contract.id().clone(),
                        amount: U128(0),
                    },
                ],
            )
            .await?;
        }
```
