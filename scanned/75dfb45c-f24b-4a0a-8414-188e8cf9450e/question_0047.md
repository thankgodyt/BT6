# Q47: invalid after windows changing before forging in st

## Question
Can an unprivileged attacker reach st' with invalid-after windows changing before forging and mempool capacity pressure, transaction IDs, conflicting transactions, era-boundary validity, and LocalTxSubmission timing, then reuse stale validation or ledger context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Mempool.hs / st'
- Entrypoint: Transaction author submits crafted transactions through LocalTxSubmission or peer propagation, then normal rollback/replay/forging paths consume the mempool state.
- Attacker controls: mempool capacity pressure, transaction IDs, conflicting transactions, era-boundary validity, and LocalTxSubmission timing.
- Exploit idea: Drive `st'` in `Ouroboros.Consensus.HardFork.Combinator.Mempool` through the production entrypoint using invalid-after windows changing before forging; verify whether the path can reuse stale validation or ledger context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Transaction ordering and ticketing must remain deterministic under duplicate, removed, and re-added transactions.
- Expected Cardano/Intersect impact: Potential High if an honest producer can forge locally accepted transactions that other honest nodes reject under equivalent state.
- Fast validation: Create a local forging test that accepts transactions, rolls back, revalidates, and validates the forged block on a second node.
