# Q3290: immutable chunk boundary reached through normal sync in mustExist

## Question
Can an unprivileged attacker reach mustExist with immutable chunk boundary reached through normal sync and ledger table diffs, snapshot age, rollback sequence, replay source, LSM/in-memory backend path, and transition across immutable/volatile storage, then confuse header/body, era, or storage context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/VolatileDB/API.hs / mustExist
- Entrypoint: Remote peers drive normal block synchronization so accepted, rejected, duplicate, or rolled-back blocks are persisted, replayed, snapshotted, or cleaned up by production storage.
- Attacker controls: ledger table diffs, snapshot age, rollback sequence, replay source, LSM/in-memory backend path, and transition across immutable/volatile storage.
- Exploit idea: Drive `mustExist` in `Ouroboros.Consensus.Storage.VolatileDB.API` through the production entrypoint using immutable chunk boundary reached through normal sync; verify whether the path can confuse header/body, era, or storage context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Snapshot selection and replay must not restore a ledger state inconsistent with the selected chain fragment.
- Expected Cardano/Intersect impact: Potential High if peer-derived storage, snapshot, replay, or rollback state causes durable use of the wrong ledger state or permanent rejection of a valid chain.
- Fast validation: Run a storage state-machine test that syncs adversarial block sequences, restarts, and compares selected tip plus ledger state hash.
