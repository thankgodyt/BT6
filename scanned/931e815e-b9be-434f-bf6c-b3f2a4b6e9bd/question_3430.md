# Q3430: transactions spanning an era transition in Ouroboros Consensus MiniProtocol Lo

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.MiniProtocol.LocalTxSubmission.Server with transactions spanning an era transition and mempool capacity pressure, transaction IDs, conflicting transactions, era-boundary validity, and LocalTxSubmission timing, then cause honest nodes to select different tips in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/LocalTxSubmission/Server.hs / Ouroboros.Consensus.MiniProtocol.LocalTxSubmission.Server
- Entrypoint: Transaction author submits crafted transactions through LocalTxSubmission or peer propagation, then normal rollback/replay/forging paths consume the mempool state.
- Attacker controls: mempool capacity pressure, transaction IDs, conflicting transactions, era-boundary validity, and LocalTxSubmission timing.
- Exploit idea: Drive `Ouroboros.Consensus.MiniProtocol.LocalTxSubmission.Server` in `Ouroboros.Consensus.MiniProtocol.LocalTxSubmission.Server` through the production entrypoint using transactions spanning an era transition; verify whether the path can cause honest nodes to select different tips before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Transaction ordering and ticketing must remain deterministic under duplicate, removed, and re-added transactions.
- Expected Cardano/Intersect impact: Potential Critical if the path lets a crafted transaction or block make an honest node accept an invalid ledger transition.
- Fast validation: Build a mempool-vs-block validation test using the same transaction and ledger state before and after rollback.
