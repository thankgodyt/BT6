### Title
Incomplete State Migration Drops Relayer Stake Data, Causing Permanent Loss of Staked NEAR — (File: `near/omni-bridge/src/migrate.rs`)

### Summary
The `migrate()` function in `near/omni-bridge/src/migrate.rs` constructs the new `Contract` state from `OldState` but silently omits the `relayers` and `relayer_config` fields. Any NEAR staked by relayers in the old state is permanently inaccessible after migration, and the relayer configuration is silently reset.

### Finding Description
`OldState` (the snapshot of the pre-upgrade contract state) declares two relayer-related fields: [1](#0-0) 

However, the `migrate()` function constructs the new `Self` without including either field: [2](#0-1) 

The new `Self { ... }` block (lines 52–74) maps every other `OldState` field to the new `Contract` but has no entry for `relayers` or `relayer_config`. The `StorageKey` enum confirms the old relayer storage prefix was deprecated (`_Relayers` with underscore): [3](#0-2) 

Because `relayer_config` is an inline (non-`LookupMap`) field serialized directly into the root state, it is completely lost after migration. For `relayers`, if the new `Contract` struct uses a different storage key prefix, all per-relayer stake entries stored under the old prefix become orphaned and unreachable.

### Impact Explanation
Relayers who staked NEAR tokens via `apply_for_trusted_relayer` to become trusted relayers hold balances recorded in `relayers: LookupMap<AccountId, RelayerState>`. After migration, those records are gone. The staked NEAR remains locked inside the contract's storage with no function able to read or return it, constituting permanent freezing of user funds. Additionally, `relayer_config` (stake threshold, waiting period) is silently reset to defaults, which can immediately change the trust model for all relayers.

### Likelihood Explanation
The `migrate()` function is `#[private]` and called by the DAO during a legitimate contract upgrade — a planned, routine operation. Any upgrade that uses this migration path will trigger the loss. The likelihood is high whenever the bridge is upgraded while relayers have active stakes.

### Recommendation
The `migrate()` function must explicitly carry forward both fields:

```rust
relayers: old_state.relayers,
relayer_config: old_state.relayer_config,
```

If the new `Contract` struct restructures relayer storage (e.g., new storage key), the migration must iterate over all entries in `old_state.relayers`, refund each staked balance to the respective relayer account, and then initialize the new relayer storage cleanly. A post-migration view function should be called to verify the integrity of the migrated state before the upgrade is considered complete.

### Proof of Concept
1. Relayer `alice.near` calls `apply_for_trusted_relayer` with a 1000 NEAR deposit; her entry is written to `relayers` under the old storage key.
2. DAO deploys a new contract version and calls `migrate()`.
3. `migrate()` constructs `Self { ... }` without `relayers` or `relayer_config`.
4. The new contract state is written; `alice.near`'s stake record no longer exists in any reachable map.
5. `alice.near` calls `resign_trusted_relayer` — the function finds no stake record and either panics or returns nothing.
6. The 1000 NEAR is permanently locked in the contract. [4](#0-3) [2](#0-1)

### Citations

**File:** near/omni-bridge/src/migrate.rs (L19-44)
```rust
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct OldState {
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
    pub destination_nonces: LookupMap<ChainKind, Nonce>,
    pub accounts_balances: LookupMap<AccountId, StorageBalance>,
    pub wnear_account_id: AccountId,
    pub provers: UnorderedMap<ChainKind, AccountId>,
    pub init_transfer_promises: LookupMap<AccountId, CryptoHash>,
    pub utxo_chain_connectors: HashMap<ChainKind, UTXOChainConfig>,
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

**File:** near/omni-bridge/src/lib.rs (L109-111)
```rust
    DeployedTokensV2,
    _Relayers,
}
```
