### Title
Relayer Stakes Permanently Lost During Contract Migration Due to Dropped State Fields - (File: `near/omni-bridge/src/migrate.rs`)

### Summary
The `migrate()` function in `near/omni-bridge/src/migrate.rs` reads `OldState` which contains `relayers: LookupMap<AccountId, RelayerState>` and `relayer_config: RelayerConfig`, but constructs the new `Contract` without carrying these fields over. The `#[trusted_relayer]` macro now manages relayer state under its own storage keys, while the old relayer data (and the NEAR tokens staked by relayers) is permanently orphaned in contract storage with no recovery path.

### Finding Description

The `OldState` struct in `migrate.rs` explicitly captures the old relayer fields: [1](#0-0) 

The `migrate()` function constructs the new `Contract` from `OldState` but silently drops `relayers` and `relayer_config`: [2](#0-1) 

The new `Contract` struct has no `relayers` or `relayer_config` fields — these are now managed by the `#[trusted_relayer]` macro from `omni_utils::macros`: [3](#0-2) 

The `StorageKey` enum retains `_Relayers` with an underscore prefix (suppressing the "unused" warning), confirming the old storage key is deprecated and the macro uses different storage keys: [4](#0-3) 

Relayers deposit NEAR tokens as stake via `apply_for_trusted_relayer` — the default `stake_required` is 1,000 NEAR: [5](#0-4) 

After migration, `resign_trusted_relayer` cannot return the stake because the relayer state no longer exists in the new contract's view. The NEAR tokens remain in the contract's account balance but are permanently untracked and unrecoverable.

### Impact Explanation

Every relayer applicant who deposited NEAR stake (up to 1,000 NEAR per relayer at the default `stake_required`) before the upgrade loses their entire stake permanently when `migrate()` is called. The NEAR tokens are trapped in the contract's balance with no state entry to authorize their return. This is a direct, irreversible financial loss to relayer applicants — an escrow mis-accounting that permanently changes user balances.

### Likelihood Explanation

The `migrate()` function is the designated upgrade path for the production `omni.bridge.near` contract. Any future upgrade that calls `migrate()` while active relayers have staked NEAR will trigger this loss. The `#[private]` guard means only the contract itself (via DAO-staged upgrade) can call it, but this is a routine, planned operation — not an edge case.

### Recommendation

In `migrate()`, explicitly carry the relayer state forward. Either:
1. Pass `old_state.relayers` and `old_state.relayer_config` into the new contract state if the `#[trusted_relayer]` macro exposes a migration constructor, or
2. Before calling `migrate()`, iterate all active relayers and return their stakes via `Promise::new(relayer).transfer(stake)`, or
3. Add a separate `migrate_relayer_stakes()` admin function that reads the old `_Relayers`-prefixed storage directly and refunds each relayer.

### Proof of Concept

1. Relayer applicant calls `apply_for_trusted_relayer` with 1,000 NEAR deposit. State is stored under the `_Relayers` storage key prefix in `LookupMap<AccountId, RelayerState>`.
2. Waiting period elapses; relayer becomes trusted. Stake is tracked in `old_state.relayers`.
3. DAO stages and deploys new contract code, then calls `migrate()`.
4. `migrate()` deserializes `OldState` (including `relayers` with the 1,000 NEAR stake record), constructs new `Contract` without `relayers` or `relayer_config`.
5. The `#[trusted_relayer]` macro initializes fresh empty relayer state under its own storage keys.
6. Relayer calls `resign_trusted_relayer` — panics or returns nothing because the macro finds no active relayer record.
7. The 1,000 NEAR remains in the contract's account balance, permanently inaccessible to the relayer.

### Citations

**File:** near/omni-bridge/src/migrate.rs (L40-44)
```rust
    pub migrated_tokens: LookupMap<AccountId, AccountId>,
    pub locked_tokens: LookupMap<(ChainKind, AccountId), u128>,
    pub relayers: LookupMap<AccountId, RelayerState>,
    pub relayer_config: RelayerConfig,
}
```

**File:** near/omni-bridge/src/migrate.rs (L50-78)
```rust
    pub fn migrate() -> Self {
        if let Some(old_state) = env::state_read::<OldState>() {
            Self {
                factories: old_state.factories,
                pending_transfers: old_state.pending_transfers,
                finalised_transfers: old_state.finalised_transfers,
                finalised_utxo_transfers: old_state.finalised_utxo_transfers,
                fast_transfers: old_state.fast_transfers,
                token_id_to_address: old_state.token_id_to_address,
                token_address_to_id: old_state.token_address_to_id,
                token_decimals: old_state.token_decimals,
                deployed_tokens: old_state.deployed_tokens,
                deployed_tokens_v2: LookupMap::new(StorageKey::DeployedTokensV2),
                token_deployer_accounts: old_state.token_deployer_accounts,
                mpc_signer: old_state.mpc_signer,
                current_origin_nonce: old_state.current_origin_nonce,
                destination_nonces: old_state.destination_nonces,
                accounts_balances: old_state.accounts_balances,
                wnear_account_id: old_state.wnear_account_id,
                provers: old_state.provers,
                init_transfer_promises: old_state.init_transfer_promises,
                utxo_chain_connectors: old_state.utxo_chain_connectors,
                migrated_tokens: old_state.migrated_tokens,
                locked_tokens: old_state.locked_tokens,
            }
        } else {
            env::panic_str("Old state not found. Migration is not needed.")
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L91-111)
```rust
#[derive(BorshSerialize, BorshStorageKey)]
enum StorageKey {
    PendingTransfers,
    Factories,
    FinalisedTransfers,
    TokenIdToAddress,
    AccountsBalances,
    TokenAddressToId,
    TokenDeployerAccounts,
    DeployedTokens,
    DestinationNonces,
    TokenDecimals,
    FastTransfers,
    RegisteredProvers,
    InitTransferPromises,
    MigratedTokens,
    FinalisedUtxoTransfers,
    LockedTokens,
    DeployedTokensV2,
    _Relayers,
}
```

**File:** near/omni-bridge/src/lib.rs (L220-243)
```rust
pub struct Contract {
    pub factories: LookupMap<ChainKind, OmniAddress>,
    pub pending_transfers: LookupMap<TransferId, TransferMessageStorage>,
    pub finalised_transfers: LookupSet<TransferId>,
    pub finalised_utxo_transfers: LookupSet<UnifiedTransferId>,
    pub fast_transfers: LookupMap<FastTransferId, FastTransferStatusStorage>,
    pub token_id_to_address: LookupMap<(ChainKind, AccountId), OmniAddress>,
    pub token_address_to_id: LookupMap<OmniAddress, AccountId>,
    pub token_decimals: LookupMap<OmniAddress, Decimals>,
    pub deployed_tokens: LookupSet<AccountId>,
    pub deployed_tokens_v2: LookupMap<AccountId, ChainKind>,
    pub token_deployer_accounts: LookupMap<ChainKind, AccountId>,
    pub mpc_signer: AccountId,
    pub current_origin_nonce: Nonce,
    // We maintain a separate nonce for each chain to optimize the storage usage on Solana by reducing the gaps.
    pub destination_nonces: LookupMap<ChainKind, Nonce>,
    pub accounts_balances: LookupMap<AccountId, StorageBalance>,
    pub wnear_account_id: AccountId,
    pub provers: UnorderedMap<ChainKind, AccountId>,
    pub init_transfer_promises: LookupMap<AccountId, CryptoHash>,
    pub utxo_chain_connectors: HashMap<ChainKind, UTXOChainConfig>,
    pub migrated_tokens: LookupMap<AccountId, AccountId>,
    pub locked_tokens: LookupMap<(ChainKind, AccountId), u128>,
}
```

**File:** near/omni-tests/src/relayer_staking.rs (L92-98)
```rust
                "stake_required": U128(1_000 * 10u128.pow(24)),
                "waiting_period_ns": U64(1_000_000_000),
            }))
            .max_gas()
            .transact()
            .await?
            .into_result()?;
```
