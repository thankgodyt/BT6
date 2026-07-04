# Q1848: index entries derived from near valid rejected blocks in getterSTM

## Question
Can an unprivileged attacker reach getterSTM with index entries derived from near-valid rejected blocks and ledger table diffs, snapshot age, rollback sequence, replay source, LSM/in-memory backend path, and transition across immutable/volatile storage, then make an invalid block or ledger state appear acceptable in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/VolatileDB/Impl.hs / getterSTM
- Entrypoint: Remote peers drive normal block synchronization so accepted, rejected, duplicate, or rolled-back blocks are persisted, replayed, snapshotted, or cleaned up by production storage.
- Attacker controls: ledger table diffs, snapshot age, rollback sequence, replay source, LSM/in-memory backend path, and transition across immutable/volatile storage.
- Exploit idea: Drive `getterSTM` in `Ouroboros.Consensus.Storage.VolatileDB.Impl` through the production entrypoint using index entries derived from near-valid rejected blocks; verify whether the path can make an invalid block or ledger state appear acceptable before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Snapshot selection and replay must not restore a ledger state inconsistent with the selected chain fragment.
- Expected Cardano/Intersect impact: Potential Medium if protocol-reachable data causes sustained storage/index churn without prohibited flood-style DoS.
- Fast validation: Create a LedgerDB snapshot/replay property comparing restored state to fresh replay from the immutable anchor.
