# Q1035: invalid after windows changing before forging in openMempoolWithoutSyncThread

## Question
Can an unprivileged attacker reach openMempoolWithoutSyncThread with invalid-after windows changing before forging and mempool capacity pressure, transaction IDs, conflicting transactions, era-boundary validity, and LocalTxSubmission timing, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Mempool/Init.hs / openMempoolWithoutSyncThread
- Entrypoint: Transaction author submits crafted transactions through LocalTxSubmission or peer propagation, then normal rollback/replay/forging paths consume the mempool state.
- Attacker controls: mempool capacity pressure, transaction IDs, conflicting transactions, era-boundary validity, and LocalTxSubmission timing.
- Exploit idea: Drive `openMempoolWithoutSyncThread` in `Ouroboros.Consensus.Mempool.Init` through the production entrypoint using invalid-after windows changing before forging; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Transaction ordering and ticketing must remain deterministic under duplicate, removed, and re-added transactions.
- Expected Cardano/Intersect impact: Potential Critical if the path lets a crafted transaction or block make an honest node accept an invalid ledger transition.
- Fast validation: Build a mempool-vs-block validation test using the same transaction and ledger state before and after rollback.
