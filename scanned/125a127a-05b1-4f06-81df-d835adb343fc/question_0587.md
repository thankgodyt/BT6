# Q587: snapshot restoration losing ledger invariants in castLedgerResult

## Question
Can an unprivileged attacker reach castLedgerResult with snapshot restoration losing ledger invariants and block body, transactions, ledger table diffs, query timing, replay order, rollback point, and state snapshot boundary, then reuse stale validation or ledger context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Basics.hs / castLedgerResult
- Entrypoint: Remote peer provides blocks/transactions that drive consensus ledger validation, replay, snapshots, or queries through normal node operation.
- Attacker controls: block body, transactions, ledger table diffs, query timing, replay order, rollback point, and state snapshot boundary.
- Exploit idea: Drive `castLedgerResult` in `Ouroboros.Consensus.Ledger.Basics` through the production entrypoint using snapshot restoration losing ledger invariants; verify whether the path can reuse stale validation or ledger context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A consensus-accepted block must have a ledger transition accepted by the ledger layer under the exact selected ledger state.
- Expected Cardano/Intersect impact: Potential High if snapshot/replay restores a ledger state inconsistent with the selected chain.
- Fast validation: Construct block-body transaction ordering tests and compare mempool acceptance against block application.
