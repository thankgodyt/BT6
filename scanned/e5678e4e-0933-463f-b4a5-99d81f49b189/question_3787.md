# Q3787: invalid block persistence followed by valid sibling arrival in TraceChunkValid

## Question
Can an unprivileged attacker reach TraceChunkValidation with invalid block persistence followed by valid sibling arrival and valid and invalid block order, file/chunk boundary reached through normal sync, ledger snapshot choice, replay order, and chain selection state, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ImmutableDB/Impl/Types.hs / TraceChunkValidation
- Entrypoint: Remote peers drive normal block synchronization so accepted, rejected, duplicate, or rolled-back blocks are persisted, replayed, snapshotted, or cleaned up by production storage.
- Attacker controls: valid and invalid block order, file/chunk boundary reached through normal sync, ledger snapshot choice, replay order, and chain selection state.
- Exploit idea: Drive `TraceChunkValidation` in `Ouroboros.Consensus.Storage.ImmutableDB.Impl.Types` through the production entrypoint using invalid block persistence followed by valid sibling arrival; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Volatile and immutable storage boundaries must not make valid blocks disappear or invalid blocks become canonical.
- Expected Cardano/Intersect impact: Potential High if a restart after normal synchronization selects a different chain than live validation.
- Fast validation: Construct a VolatileDB/ImmutableDB boundary test with duplicate and stale blocks and assert indexes resolve the same point before and after cleanup.
