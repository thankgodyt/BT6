# Q3543: volatile cleanup while a candidate needs ancestors in getPastLedgerAt

## Question
Can an unprivileged attacker reach getPastLedgerAt with volatile cleanup while a candidate needs ancestors and block body bytes, index entries derived from accepted blocks, orphaned descendants, cleanup timing, and repeated near-valid candidates, then cause honest nodes to select different tips in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/LedgerDB/V2/LedgerSeq.hs / getPastLedgerAt
- Entrypoint: Remote peers drive normal block synchronization so accepted, rejected, duplicate, or rolled-back blocks are persisted, replayed, snapshotted, or cleaned up by production storage.
- Attacker controls: block body bytes, index entries derived from accepted blocks, orphaned descendants, cleanup timing, and repeated near-valid candidates.
- Exploit idea: Drive `getPastLedgerAt` in `Ouroboros.Consensus.Storage.LedgerDB.V2.LedgerSeq` through the production entrypoint using volatile cleanup while a candidate needs ancestors; verify whether the path can cause honest nodes to select different tips before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Duplicate, stale, or near-valid peer data must not cause durable database state that blocks future valid synchronization.
- Expected Cardano/Intersect impact: Potential Medium if protocol-reachable data causes sustained storage/index churn without prohibited flood-style DoS.
- Fast validation: Create a LedgerDB snapshot/replay property comparing restored state to fresh replay from the immutable anchor.
