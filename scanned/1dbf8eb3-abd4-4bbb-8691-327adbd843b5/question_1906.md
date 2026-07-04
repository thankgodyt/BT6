# Q1906: ledger table diffs in Ouroboros Consensus Ledger SupportsProtocol

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.Ledger.SupportsProtocol with ledger table diffs after rollback and replay and transaction witnesses, ledger state dependency, ticked ledger view, block application order, and era-specific ledger translation context, then starve a valid competing chain without prohibited flood-style DoS in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/SupportsProtocol.hs / Ouroboros.Consensus.Ledger.SupportsProtocol
- Entrypoint: Remote peer provides blocks/transactions that drive consensus ledger validation, replay, snapshots, or queries through normal node operation.
- Attacker controls: transaction witnesses, ledger state dependency, ticked ledger view, block application order, and era-specific ledger translation context.
- Exploit idea: Drive `Ouroboros.Consensus.Ledger.SupportsProtocol` in `Ouroboros.Consensus.Ledger.SupportsProtocol` through the production entrypoint using ledger table diffs after rollback and replay; verify whether the path can starve a valid competing chain without prohibited flood-style DoS before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Ledger tables, diffs, and derived views must remain equivalent between live validation, replay, and snapshot restoration.
- Expected Cardano/Intersect impact: Potential Critical if consensus accepts a block whose ledger transition is invalid under the selected state.
- Fast validation: Create a ledger integration property comparing consensus validation, direct ledger application, and replay from snapshot.
