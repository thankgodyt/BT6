# Q511: restart in simpleChunkInfo

## Question
Can an unprivileged attacker reach simpleChunkInfo with restart after receiving duplicate valid and invalid blocks and peer-delivered blocks, duplicate block hashes, rollback depth, immutable boundary timing, volatile suffix contents, snapshot cadence, and restart timing, then make a valid block permanently or durably rejected in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ImmutableDB/Chunks/Internal.hs / simpleChunkInfo
- Entrypoint: Remote peers drive normal block synchronization so accepted, rejected, duplicate, or rolled-back blocks are persisted, replayed, snapshotted, or cleaned up by production storage.
- Attacker controls: peer-delivered blocks, duplicate block hashes, rollback depth, immutable boundary timing, volatile suffix contents, snapshot cadence, and restart timing.
- Exploit idea: Drive `simpleChunkInfo` in `Ouroboros.Consensus.Storage.ImmutableDB.Chunks.Internal` through the production entrypoint using restart after receiving duplicate valid and invalid blocks; verify whether the path can make a valid block permanently or durably rejected before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Persisted blocks, indexes, snapshots, and ledger states must replay to the same selected chain as the pre-restart node state.
- Expected Cardano/Intersect impact: Potential High if a restart after normal synchronization selects a different chain than live validation.
- Fast validation: Construct a VolatileDB/ImmutableDB boundary test with duplicate and stale blocks and assert indexes resolve the same point before and after cleanup.
