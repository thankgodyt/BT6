# Q3933: transactions spanning an era transition in MaxTxSizeUTxO

## Question
Can an unprivileged attacker reach MaxTxSizeUTxO with transactions spanning an era transition and mempool capacity pressure, transaction IDs, conflicting transactions, era-boundary validity, and LocalTxSubmission timing, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Mempool.hs / MaxTxSizeUTxO
- Entrypoint: Transaction author submits crafted transactions through LocalTxSubmission or peer propagation, then normal rollback/replay/forging paths consume the mempool state.
- Attacker controls: mempool capacity pressure, transaction IDs, conflicting transactions, era-boundary validity, and LocalTxSubmission timing.
- Exploit idea: Drive `MaxTxSizeUTxO` in `Ouroboros.Consensus.Shelley.Ledger.Mempool` through the production entrypoint using transactions spanning an era transition; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Transaction ordering and ticketing must remain deterministic under duplicate, removed, and re-added transactions.
- Expected Cardano/Intersect impact: Potential High if an honest producer can forge locally accepted transactions that other honest nodes reject under equivalent state.
- Fast validation: Create a local forging test that accepts transactions, rolls back, revalidates, and validates the forged block on a second node.
