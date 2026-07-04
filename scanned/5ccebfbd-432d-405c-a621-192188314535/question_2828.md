# Q2828: snapshot restoration losing ledger invariants in Ouroboros Consensus Ledger Su

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.Ledger.SupportsProtocol with snapshot restoration losing ledger invariants and block body, transactions, ledger table diffs, query timing, replay order, rollback point, and state snapshot boundary, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/SupportsProtocol.hs / Ouroboros.Consensus.Ledger.SupportsProtocol
- Entrypoint: Remote peer provides blocks/transactions that drive consensus ledger validation, replay, snapshots, or queries through normal node operation.
- Attacker controls: block body, transactions, ledger table diffs, query timing, replay order, rollback point, and state snapshot boundary.
- Exploit idea: Drive `Ouroboros.Consensus.Ledger.SupportsProtocol` in `Ouroboros.Consensus.Ledger.SupportsProtocol` through the production entrypoint using snapshot restoration losing ledger invariants; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A consensus-accepted block must have a ledger transition accepted by the ledger layer under the exact selected ledger state.
- Expected Cardano/Intersect impact: Potential Critical if consensus accepts a block whose ledger transition is invalid under the selected state.
- Fast validation: Create a ledger integration property comparing consensus validation, direct ledger application, and replay from snapshot.
