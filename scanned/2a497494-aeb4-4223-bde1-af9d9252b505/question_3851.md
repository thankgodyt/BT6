# Q3851: snapshot restoration losing ledger invariants in fromSetDeletes

## Question
Can an unprivileged attacker reach fromSetDeletes with snapshot restoration losing ledger invariants and block body, transactions, ledger table diffs, query timing, replay order, rollback point, and state snapshot boundary, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Tables/Diff.hs / fromSetDeletes
- Entrypoint: Remote peer provides blocks/transactions that drive consensus ledger validation, replay, snapshots, or queries through normal node operation.
- Attacker controls: block body, transactions, ledger table diffs, query timing, replay order, rollback point, and state snapshot boundary.
- Exploit idea: Drive `fromSetDeletes` in `Ouroboros.Consensus.Ledger.Tables.Diff` through the production entrypoint using snapshot restoration losing ledger invariants; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A consensus-accepted block must have a ledger transition accepted by the ledger layer under the exact selected ledger state.
- Expected Cardano/Intersect impact: Potential High if snapshot/replay restores a ledger state inconsistent with the selected chain.
- Fast validation: Construct block-body transaction ordering tests and compare mempool acceptance against block application.
