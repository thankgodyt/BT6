# Q1501: snapshot selection in BlockOffset

## Question
Can an unprivileged attacker reach BlockOffset with snapshot selection after rollback and replay and valid and invalid block order, file/chunk boundary reached through normal sync, ledger snapshot choice, replay order, and chain selection state, then make an invalid block or ledger state appear acceptable in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ImmutableDB/Impl/Index/Secondary.hs / BlockOffset
- Entrypoint: Remote peers drive normal block synchronization so accepted, rejected, duplicate, or rolled-back blocks are persisted, replayed, snapshotted, or cleaned up by production storage.
- Attacker controls: valid and invalid block order, file/chunk boundary reached through normal sync, ledger snapshot choice, replay order, and chain selection state.
- Exploit idea: Drive `BlockOffset` in `Ouroboros.Consensus.Storage.ImmutableDB.Impl.Index.Secondary` through the production entrypoint using snapshot selection after rollback and replay; verify whether the path can make an invalid block or ledger state appear acceptable before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Volatile and immutable storage boundaries must not make valid blocks disappear or invalid blocks become canonical.
- Expected Cardano/Intersect impact: Potential High if a restart after normal synchronization selects a different chain than live validation.
- Fast validation: Construct a VolatileDB/ImmutableDB boundary test with duplicate and stale blocks and assert indexes resolve the same point before and after cleanup.
