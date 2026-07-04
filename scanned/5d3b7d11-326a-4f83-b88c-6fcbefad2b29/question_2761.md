# Q2761: immutable chunk boundary reached through normal sync in getOffsetFromPrimaryIn

## Question
Can an unprivileged attacker reach getOffsetFromPrimaryIndex with immutable chunk boundary reached through normal sync and ledger table diffs, snapshot age, rollback sequence, replay source, LSM/in-memory backend path, and transition across immutable/volatile storage, then starve a valid competing chain without prohibited flood-style DoS in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ImmutableDB/Impl/Index/Cache.hs / getOffsetFromPrimaryIndex
- Entrypoint: Remote peers drive normal block synchronization so accepted, rejected, duplicate, or rolled-back blocks are persisted, replayed, snapshotted, or cleaned up by production storage.
- Attacker controls: ledger table diffs, snapshot age, rollback sequence, replay source, LSM/in-memory backend path, and transition across immutable/volatile storage.
- Exploit idea: Drive `getOffsetFromPrimaryIndex` in `Ouroboros.Consensus.Storage.ImmutableDB.Impl.Index.Cache` through the production entrypoint using immutable chunk boundary reached through normal sync; verify whether the path can starve a valid competing chain without prohibited flood-style DoS before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Snapshot selection and replay must not restore a ledger state inconsistent with the selected chain fragment.
- Expected Cardano/Intersect impact: Potential High if peer-derived storage, snapshot, replay, or rollback state causes durable use of the wrong ledger state or permanent rejection of a valid chain.
- Fast validation: Run a storage state-machine test that syncs adversarial block sequences, restarts, and compares selected tip plus ledger state hash.
