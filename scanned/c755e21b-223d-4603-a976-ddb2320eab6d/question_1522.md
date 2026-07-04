# Q1522: orphaned descendants retained across recovery in nextFile

## Question
Can an unprivileged attacker reach nextFile with orphaned descendants retained across recovery and block body bytes, index entries derived from accepted blocks, orphaned descendants, cleanup timing, and repeated near-valid candidates, then reuse stale validation or ledger context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/VolatileDB/Impl.hs / nextFile
- Entrypoint: Remote peers drive normal block synchronization so accepted, rejected, duplicate, or rolled-back blocks are persisted, replayed, snapshotted, or cleaned up by production storage.
- Attacker controls: block body bytes, index entries derived from accepted blocks, orphaned descendants, cleanup timing, and repeated near-valid candidates.
- Exploit idea: Drive `nextFile` in `Ouroboros.Consensus.Storage.VolatileDB.Impl` through the production entrypoint using orphaned descendants retained across recovery; verify whether the path can reuse stale validation or ledger context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Duplicate, stale, or near-valid peer data must not cause durable database state that blocks future valid synchronization.
- Expected Cardano/Intersect impact: Potential High if a restart after normal synchronization selects a different chain than live validation.
- Fast validation: Construct a VolatileDB/ImmutableDB boundary test with duplicate and stale blocks and assert indexes resolve the same point before and after cleanup.
