# Q261: era specific ledger data through hard fork wrappers in BlockProtocol

## Question
Can an unprivileged attacker reach BlockProtocol with era-specific ledger data through hard-fork wrappers and transaction witnesses, ledger state dependency, ticked ledger view, block application order, and era-specific ledger translation context, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Dual.hs / BlockProtocol
- Entrypoint: Remote peer provides blocks/transactions that drive consensus ledger validation, replay, snapshots, or queries through normal node operation.
- Attacker controls: transaction witnesses, ledger state dependency, ticked ledger view, block application order, and era-specific ledger translation context.
- Exploit idea: Drive `BlockProtocol` in `Ouroboros.Consensus.Ledger.Dual` through the production entrypoint using era-specific ledger data through hard-fork wrappers; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Ledger tables, diffs, and derived views must remain equivalent between live validation, replay, and snapshot restoration.
- Expected Cardano/Intersect impact: Potential Critical if consensus accepts a block whose ledger transition is invalid under the selected state.
- Fast validation: Create a ledger integration property comparing consensus validation, direct ledger application, and replay from snapshot.
