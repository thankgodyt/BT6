# Q2470: volatile cleanup while a candidate needs ancestors in snapshotToUTxOSizeFilePa

## Question
Can an unprivileged attacker reach snapshotToUTxOSizeFilePath with volatile cleanup while a candidate needs ancestors and block body bytes, index entries derived from accepted blocks, orphaned descendants, cleanup timing, and repeated near-valid candidates, then cause honest nodes to select different tips in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus-lsm/Ouroboros/Consensus/Storage/LedgerDB/V2/LSM.hs / snapshotToUTxOSizeFilePath
- Entrypoint: Remote peers drive normal block synchronization so accepted, rejected, duplicate, or rolled-back blocks are persisted, replayed, snapshotted, or cleaned up by production storage.
- Attacker controls: block body bytes, index entries derived from accepted blocks, orphaned descendants, cleanup timing, and repeated near-valid candidates.
- Exploit idea: Drive `snapshotToUTxOSizeFilePath` in `Ouroboros.Consensus.Storage.LedgerDB.V2.LSM` through the production entrypoint using volatile cleanup while a candidate needs ancestors; verify whether the path can cause honest nodes to select different tips before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Duplicate, stale, or near-valid peer data must not cause durable database state that blocks future valid synchronization.
- Expected Cardano/Intersect impact: Potential High if peer-derived storage, snapshot, replay, or rollback state causes durable use of the wrong ledger state or permanent rejection of a valid chain.
- Fast validation: Run a storage state-machine test that syncs adversarial block sequences, restarts, and compares selected tip plus ledger state hash.
