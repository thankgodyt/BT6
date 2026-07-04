# Q599: block application using a ticked state different from header validation in K2

## Question
Can an unprivileged attacker reach K2 with block application using a ticked state different from header validation and block body, transactions, ledger table diffs, query timing, replay order, rollback point, and state snapshot boundary, then make a valid block permanently or durably rejected in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Tables/Combinators.hs / K2
- Entrypoint: Remote peer provides blocks/transactions that drive consensus ledger validation, replay, snapshots, or queries through normal node operation.
- Attacker controls: block body, transactions, ledger table diffs, query timing, replay order, rollback point, and state snapshot boundary.
- Exploit idea: Drive `K2` in `Ouroboros.Consensus.Ledger.Tables.Combinators` through the production entrypoint using block application using a ticked state different from header validation; verify whether the path can make a valid block permanently or durably rejected before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A consensus-accepted block must have a ledger transition accepted by the ledger layer under the exact selected ledger state.
- Expected Cardano/Intersect impact: Potential High if snapshot/replay restores a ledger state inconsistent with the selected chain.
- Fast validation: Construct block-body transaction ordering tests and compare mempool acceptance against block application.
