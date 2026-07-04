# Q3293: orphaned descendants retained across recovery in modifyIndex

## Question
Can an unprivileged attacker reach modifyIndex with orphaned descendants retained across recovery and block body bytes, index entries derived from accepted blocks, orphaned descendants, cleanup timing, and repeated near-valid candidates, then make a valid block permanently or durably rejected in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/VolatileDB/Impl/Index.hs / modifyIndex
- Entrypoint: Remote peers drive normal block synchronization so accepted, rejected, duplicate, or rolled-back blocks are persisted, replayed, snapshotted, or cleaned up by production storage.
- Attacker controls: block body bytes, index entries derived from accepted blocks, orphaned descendants, cleanup timing, and repeated near-valid candidates.
- Exploit idea: Drive `modifyIndex` in `Ouroboros.Consensus.Storage.VolatileDB.Impl.Index` through the production entrypoint using orphaned descendants retained across recovery; verify whether the path can make a valid block permanently or durably rejected before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Duplicate, stale, or near-valid peer data must not cause durable database state that blocks future valid synchronization.
- Expected Cardano/Intersect impact: Potential High if peer-derived storage, snapshot, replay, or rollback state causes durable use of the wrong ledger state or permanent rejection of a valid chain.
- Fast validation: Run a storage state-machine test that syncs adversarial block sequences, restarts, and compares selected tip plus ledger state hash.
