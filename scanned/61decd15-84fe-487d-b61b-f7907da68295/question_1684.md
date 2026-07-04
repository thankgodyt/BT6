# Q1684: transactions spanning an era transition in reapplyShelleyTx

## Question
Can an unprivileged attacker reach reapplyShelleyTx with transactions spanning an era transition and mempool capacity pressure, transaction IDs, conflicting transactions, era-boundary validity, and LocalTxSubmission timing, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Mempool.hs / reapplyShelleyTx
- Entrypoint: Transaction author submits crafted transactions through LocalTxSubmission or peer propagation, then normal rollback/replay/forging paths consume the mempool state.
- Attacker controls: mempool capacity pressure, transaction IDs, conflicting transactions, era-boundary validity, and LocalTxSubmission timing.
- Exploit idea: Drive `reapplyShelleyTx` in `Ouroboros.Consensus.Shelley.Ledger.Mempool` through the production entrypoint using transactions spanning an era transition; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Transaction ordering and ticketing must remain deterministic under duplicate, removed, and re-added transactions.
- Expected Cardano/Intersect impact: Potential Medium if peer-submitted transactions create sustained validation churn without prohibited flood-style DoS.
- Fast validation: Write a TxSeq/property test for duplicate submit/remove/re-add sequences and assert deterministic ordering.
