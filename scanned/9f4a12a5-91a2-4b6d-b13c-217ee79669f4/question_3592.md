# Q3592: mempool acceptance compared in LedgerSupportsPeerSelection

## Question
Can an unprivileged attacker reach LedgerSupportsPeerSelection with mempool acceptance compared with block application and ledger tables, diffs, mempool transactions, snapshot selection, state-query target, and block validation timing, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/SupportsPeerSelection.hs / LedgerSupportsPeerSelection
- Entrypoint: Remote peer provides blocks/transactions that drive consensus ledger validation, replay, snapshots, or queries through normal node operation.
- Attacker controls: ledger tables, diffs, mempool transactions, snapshot selection, state-query target, and block validation timing.
- Exploit idea: Drive `LedgerSupportsPeerSelection` in `Ouroboros.Consensus.Ledger.SupportsPeerSelection` through the production entrypoint using mempool acceptance compared with block application; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A query or inspection path must not expose or use stale ledger state in a way that affects validation or block production.
- Expected Cardano/Intersect impact: Potential High if snapshot/replay restores a ledger state inconsistent with the selected chain.
- Fast validation: Construct block-body transaction ordering tests and compare mempool acceptance against block application.
