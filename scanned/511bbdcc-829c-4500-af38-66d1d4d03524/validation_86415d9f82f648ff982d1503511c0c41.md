### Title
`Contract::migrate()` Silently Drops Relayer State, Causing Permanent Loss of Staked NEAR Funds - (`File: near/omni-bridge/src/migrate.rs`)

### Summary

The `migrate()` function in `near/omni-bridge/src/migrate.rs` reads the old contract state (which includes `relayers` and `relayer_config`) but constructs the new `Contract` without transferring those fields. All relayer stake records and configuration are silently discarded, permanently freezing any NEAR tokens that relayers had staked.

### Finding Description

`OldState` (the pre-migration contract state) contains two fields that are absent from the new `Contract` struct:

```rust
// near/omni-bridge/src/migrate.rs  lines 42-43
pub relayers: LookupMap<AccountId, RelayerState>,
pub relayer_config: RelayerConfig,
```

The new `Contract` struct (lines 220–243 of `lib.rs`) does not declare these fields explicitly; they are managed by the `#[trusted_relayer]` proc-macro, which uses its own storage keys. The deprecated `StorageKey::_Relayers` variant (line 110 of `lib.rs`) confirms the old key is no longer used.

The `migrate()` function reads `OldState` successfully but constructs `Self` without mapping `old_state.relayers` or `old_state.relayer_config` to the macro's new storage layout:

```rust
// near/omni-bridge/src/migrate.rs  lines 50-74
pub fn migrate() -> Self {
    if let Some(old_state) = env::state_read::<OldState>() {
        Self {
            factories: old_state.factories,
            ...
            locked_tokens: old_state.locked_tokens,
            // relayers and relayer_config are silently dropped
        }
    } else { ... }
}
```

After migration the `#[trusted_relayer]` macro initialises its internal storage from scratch (empty), so every relayer's stake record and the global `RelayerConfig` are gone.

### Impact Explanation

Relayers who called `apply_for_trusted_relayer` and deposited NEAR tokens as stake have those tokens held inside the contract's account balance. The only way to withdraw them is through `resign_trusted_relayer` or `reject_relayer_application`, both of which look up the relayer's entry in the macro-managed storage. After migration that storage is empty, so no withdrawal path exists. The staked NEAR is permanently frozen inside the contract. Additionally, the `RelayerConfig` (stake threshold, waiting period) reverts to hard-coded defaults, silently changing the trust model for all future relayer applications.

### Likelihood Explanation

`migrate()` is a planned, one-time upgrade operation. It will be called exactly once during the next contract upgrade. Every relayer that staked before the upgrade is affected with certainty; no attacker action is required.

### Recommendation

Inside `migrate()`, explicitly copy the old relayer state into the macro's storage before returning the new `Self`. Concretely, iterate over `old_state.relayers` and write each entry to the storage key the `#[trusted_relayer]` macro expects, and call the macro's config setter with `old_state.relayer_config`. Alternatively, if the macro exposes a constructor that accepts pre-existing state, use it during migration.

### Proof of Concept

1. Relayer Alice calls `apply_for_trusted_relayer` with 1 000 NEAR deposit → `RelayerState` entry written to `StorageKey::_Relayers`.
2. DAO deploys new contract code and calls `migrate()`.
3. `migrate()` deserialises `OldState` (Alice's entry is present), constructs new `Contract` without Alice's entry, writes new state.
4. Alice calls `resign_trusted_relayer` → macro looks up Alice in its (empty) storage → panics / returns "not a relayer".
5. Alice's 1 000 NEAR is permanently locked in the contract with no withdrawal path. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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
