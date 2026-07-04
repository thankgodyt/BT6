# Q3268: snapshot selection in prevChunkNo

## Question
Can an unprivileged attacker reach prevChunkNo with snapshot selection after rollback and replay and valid and invalid block order, file/chunk boundary reached through normal sync, ledger snapshot choice, replay order, and chain selection state, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ImmutableDB/Chunks/Internal.hs / prevChunkNo
- Entrypoint: Remote peers drive normal block synchronization so accepted, rejected, duplicate, or rolled-back blocks are persisted, replayed, snapshotted, or cleaned up by production storage.
- Attacker controls: valid and invalid block order, file/chunk boundary reached through normal sync, ledger snapshot choice, replay order, and chain selection state.
- Exploit idea: Drive `prevChunkNo` in `Ouroboros.Consensus.Storage.ImmutableDB.Chunks.Internal` through the production entrypoint using snapshot selection after rollback and replay; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Volatile and immutable storage boundaries must not make valid blocks disappear or invalid blocks become canonical.
- Expected Cardano/Intersect impact: Potential High if a restart after normal synchronization selects a different chain than live validation.
- Fast validation: Construct a VolatileDB/ImmutableDB boundary test with duplicate and stale blocks and assert indexes resolve the same point before and after cleanup.
