# Q2664: invalid after windows changing before forging in pureRemoveTxs

## Question
Can an unprivileged attacker reach pureRemoveTxs with invalid-after windows changing before forging and mempool capacity pressure, transaction IDs, conflicting transactions, era-boundary validity, and LocalTxSubmission timing, then reuse stale validation or ledger context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Mempool/Update.hs / pureRemoveTxs
- Entrypoint: Transaction author submits crafted transactions through LocalTxSubmission or peer propagation, then normal rollback/replay/forging paths consume the mempool state.
- Attacker controls: mempool capacity pressure, transaction IDs, conflicting transactions, era-boundary validity, and LocalTxSubmission timing.
- Exploit idea: Drive `pureRemoveTxs` in `Ouroboros.Consensus.Mempool.Update` through the production entrypoint using invalid-after windows changing before forging; verify whether the path can reuse stale validation or ledger context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Transaction ordering and ticketing must remain deterministic under duplicate, removed, and re-added transactions.
- Expected Cardano/Intersect impact: Potential Medium if peer-submitted transactions create sustained validation churn without prohibited flood-style DoS.
- Fast validation: Write a TxSeq/property test for duplicate submit/remove/re-add sequences and assert deterministic ordering.
