# Q2560: snapshot restoration losing ledger invariants in HasLedgerTables

## Question
Can an unprivileged attacker reach HasLedgerTables with snapshot restoration losing ledger invariants and block body, transactions, ledger table diffs, query timing, replay order, rollback point, and state snapshot boundary, then make a valid block permanently or durably rejected in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Tables.hs / HasLedgerTables
- Entrypoint: Remote peer provides blocks/transactions that drive consensus ledger validation, replay, snapshots, or queries through normal node operation.
- Attacker controls: block body, transactions, ledger table diffs, query timing, replay order, rollback point, and state snapshot boundary.
- Exploit idea: Drive `HasLedgerTables` in `Ouroboros.Consensus.Ledger.Tables.Basics` through the production entrypoint using snapshot restoration losing ledger invariants; verify whether the path can make a valid block permanently or durably rejected before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A consensus-accepted block must have a ledger transition accepted by the ledger layer under the exact selected ledger state.
- Expected Cardano/Intersect impact: Potential Critical if consensus accepts a block whose ledger transition is invalid under the selected state.
- Fast validation: Create a ledger integration property comparing consensus validation, direct ledger application, and replay from snapshot.
