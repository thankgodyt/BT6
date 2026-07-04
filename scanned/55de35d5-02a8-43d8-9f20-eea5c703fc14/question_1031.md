# Q1031: transactions spanning an era transition in Ouroboros Consensus Mempool

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.Mempool with transactions spanning an era transition and mempool capacity pressure, transaction IDs, conflicting transactions, era-boundary validity, and LocalTxSubmission timing, then cause honest nodes to select different tips in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Mempool.hs / Ouroboros.Consensus.Mempool
- Entrypoint: Transaction author submits crafted transactions through LocalTxSubmission or peer propagation, then normal rollback/replay/forging paths consume the mempool state.
- Attacker controls: mempool capacity pressure, transaction IDs, conflicting transactions, era-boundary validity, and LocalTxSubmission timing.
- Exploit idea: Drive `Ouroboros.Consensus.Mempool` in `Ouroboros.Consensus.Mempool` through the production entrypoint using transactions spanning an era transition; verify whether the path can cause honest nodes to select different tips before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Transaction ordering and ticketing must remain deterministic under duplicate, removed, and re-added transactions.
- Expected Cardano/Intersect impact: Potential Medium if peer-submitted transactions create sustained validation churn without prohibited flood-style DoS.
- Fast validation: Write a TxSeq/property test for duplicate submit/remove/re-add sequences and assert deterministic ordering.
