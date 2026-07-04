# Q2500: restart in getIsMember

## Question
Can an unprivileged attacker reach getIsMember with restart after receiving duplicate valid and invalid blocks and peer-delivered blocks, duplicate block hashes, rollback depth, immutable boundary timing, volatile suffix contents, snapshot cadence, and restart timing, then reuse stale validation or ledger context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/VolatileDB/API.hs / getIsMember
- Entrypoint: Remote peers drive normal block synchronization so accepted, rejected, duplicate, or rolled-back blocks are persisted, replayed, snapshotted, or cleaned up by production storage.
- Attacker controls: peer-delivered blocks, duplicate block hashes, rollback depth, immutable boundary timing, volatile suffix contents, snapshot cadence, and restart timing.
- Exploit idea: Drive `getIsMember` in `Ouroboros.Consensus.Storage.VolatileDB.API` through the production entrypoint using restart after receiving duplicate valid and invalid blocks; verify whether the path can reuse stale validation or ledger context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Persisted blocks, indexes, snapshots, and ledger states must replay to the same selected chain as the pre-restart node state.
- Expected Cardano/Intersect impact: Potential High if peer-derived storage, snapshot, replay, or rollback state causes durable use of the wrong ledger state or permanent rejection of a valid chain.
- Fast validation: Run a storage state-machine test that syncs adversarial block sequences, restarts, and compares selected tip plus ledger state hash.
