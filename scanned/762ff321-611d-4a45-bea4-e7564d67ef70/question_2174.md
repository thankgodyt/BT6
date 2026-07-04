# Q2174: restart in Ouroboros Consensus Storage VolatileDB Impl

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.Storage.VolatileDB.Impl with restart after receiving duplicate valid and invalid blocks and peer-delivered blocks, duplicate block hashes, rollback depth, immutable boundary timing, volatile suffix contents, snapshot cadence, and restart timing, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/VolatileDB/Impl.hs / Ouroboros.Consensus.Storage.VolatileDB.Impl
- Entrypoint: Remote peers drive normal block synchronization so accepted, rejected, duplicate, or rolled-back blocks are persisted, replayed, snapshotted, or cleaned up by production storage.
- Attacker controls: peer-delivered blocks, duplicate block hashes, rollback depth, immutable boundary timing, volatile suffix contents, snapshot cadence, and restart timing.
- Exploit idea: Drive `Ouroboros.Consensus.Storage.VolatileDB.Impl` in `Ouroboros.Consensus.Storage.VolatileDB.Impl` through the production entrypoint using restart after receiving duplicate valid and invalid blocks; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Persisted blocks, indexes, snapshots, and ledger states must replay to the same selected chain as the pre-restart node state.
- Expected Cardano/Intersect impact: Potential High if peer-derived storage, snapshot, replay, or rollback state causes durable use of the wrong ledger state or permanent rejection of a valid chain.
- Fast validation: Run a storage state-machine test that syncs adversarial block sequences, restarts, and compares selected tip plus ledger state hash.
