# Q1166: snapshot selection in Ouroboros Consensus Storage ImmutableDB Chunks

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.Storage.ImmutableDB.Chunks with snapshot selection after rollback and replay and valid and invalid block order, file/chunk boundary reached through normal sync, ledger snapshot choice, replay order, and chain selection state, then confuse header/body, era, or storage context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ImmutableDB/Chunks.hs / Ouroboros.Consensus.Storage.ImmutableDB.Chunks
- Entrypoint: Remote peers drive normal block synchronization so accepted, rejected, duplicate, or rolled-back blocks are persisted, replayed, snapshotted, or cleaned up by production storage.
- Attacker controls: valid and invalid block order, file/chunk boundary reached through normal sync, ledger snapshot choice, replay order, and chain selection state.
- Exploit idea: Drive `Ouroboros.Consensus.Storage.ImmutableDB.Chunks` in `Ouroboros.Consensus.Storage.ImmutableDB.Chunks` through the production entrypoint using snapshot selection after rollback and replay; verify whether the path can confuse header/body, era, or storage context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Volatile and immutable storage boundaries must not make valid blocks disappear or invalid blocks become canonical.
- Expected Cardano/Intersect impact: Potential Medium if protocol-reachable data causes sustained storage/index churn without prohibited flood-style DoS.
- Fast validation: Create a LedgerDB snapshot/replay property comparing restored state to fresh replay from the immutable anchor.
