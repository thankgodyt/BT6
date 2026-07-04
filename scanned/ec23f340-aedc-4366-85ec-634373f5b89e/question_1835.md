# Q1835: volatile cleanup while a candidate needs ancestors in doOpenDB

## Question
Can an unprivileged attacker reach doOpenDB with volatile cleanup while a candidate needs ancestors and block body bytes, index entries derived from accepted blocks, orphaned descendants, cleanup timing, and repeated near-valid candidates, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/LedgerDB.hs / doOpenDB
- Entrypoint: Remote peers drive normal block synchronization so accepted, rejected, duplicate, or rolled-back blocks are persisted, replayed, snapshotted, or cleaned up by production storage.
- Attacker controls: block body bytes, index entries derived from accepted blocks, orphaned descendants, cleanup timing, and repeated near-valid candidates.
- Exploit idea: Drive `doOpenDB` in `Ouroboros.Consensus.Storage.LedgerDB.API` through the production entrypoint using volatile cleanup while a candidate needs ancestors; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Duplicate, stale, or near-valid peer data must not cause durable database state that blocks future valid synchronization.
- Expected Cardano/Intersect impact: Potential High if a restart after normal synchronization selects a different chain than live validation.
- Fast validation: Construct a VolatileDB/ImmutableDB boundary test with duplicate and stale blocks and assert indexes resolve the same point before and after cleanup.
