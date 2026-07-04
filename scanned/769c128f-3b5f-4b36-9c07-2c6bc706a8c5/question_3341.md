# Q3341: ledger table diffs in ltap

## Question
Can an unprivileged attacker reach ltap with ledger table diffs after rollback and replay and transaction witnesses, ledger state dependency, ticked ledger view, block application order, and era-specific ledger translation context, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Tables/Combinators.hs / ltap
- Entrypoint: Remote peer provides blocks/transactions that drive consensus ledger validation, replay, snapshots, or queries through normal node operation.
- Attacker controls: transaction witnesses, ledger state dependency, ticked ledger view, block application order, and era-specific ledger translation context.
- Exploit idea: Drive `ltap` in `Ouroboros.Consensus.Ledger.Tables.Combinators` through the production entrypoint using ledger table diffs after rollback and replay; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Ledger tables, diffs, and derived views must remain equivalent between live validation, replay, and snapshot restoration.
- Expected Cardano/Intersect impact: Potential High if snapshot/replay restores a ledger state inconsistent with the selected chain.
- Fast validation: Construct block-body transaction ordering tests and compare mempool acceptance against block application.
