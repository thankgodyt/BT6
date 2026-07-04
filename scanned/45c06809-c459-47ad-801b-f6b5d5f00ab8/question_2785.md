# Q2785: index entries derived from near valid rejected blocks in ReverseIndex

## Question
Can an unprivileged attacker reach ReverseIndex with index entries derived from near-valid rejected blocks and ledger table diffs, snapshot age, rollback sequence, replay source, LSM/in-memory backend path, and transition across immutable/volatile storage, then confuse header/body, era, or storage context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/VolatileDB/Impl/Types.hs / ReverseIndex
- Entrypoint: Remote peers drive normal block synchronization so accepted, rejected, duplicate, or rolled-back blocks are persisted, replayed, snapshotted, or cleaned up by production storage.
- Attacker controls: ledger table diffs, snapshot age, rollback sequence, replay source, LSM/in-memory backend path, and transition across immutable/volatile storage.
- Exploit idea: Drive `ReverseIndex` in `Ouroboros.Consensus.Storage.VolatileDB.Impl.Types` through the production entrypoint using index entries derived from near-valid rejected blocks; verify whether the path can confuse header/body, era, or storage context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Snapshot selection and replay must not restore a ledger state inconsistent with the selected chain fragment.
- Expected Cardano/Intersect impact: Potential High if a restart after normal synchronization selects a different chain than live validation.
- Fast validation: Construct a VolatileDB/ImmutableDB boundary test with duplicate and stale blocks and assert indexes resolve the same point before and after cleanup.
