# Q1911: mempool acceptance compared in LedgerStateKind

## Question
Can an unprivileged attacker reach LedgerStateKind with mempool acceptance compared with block application and ledger tables, diffs, mempool transactions, snapshot selection, state-query target, and block validation timing, then cause honest nodes to select different tips in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Tables/Kinds.hs / LedgerStateKind
- Entrypoint: Remote peer provides blocks/transactions that drive consensus ledger validation, replay, snapshots, or queries through normal node operation.
- Attacker controls: ledger tables, diffs, mempool transactions, snapshot selection, state-query target, and block validation timing.
- Exploit idea: Drive `LedgerStateKind` in `Ouroboros.Consensus.Ledger.Tables.Kinds` through the production entrypoint using mempool acceptance compared with block application; verify whether the path can cause honest nodes to select different tips before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A query or inspection path must not expose or use stale ledger state in a way that affects validation or block production.
- Expected Cardano/Intersect impact: Potential High if snapshot/replay restores a ledger state inconsistent with the selected chain.
- Fast validation: Construct block-body transaction ordering tests and compare mempool acceptance against block application.
