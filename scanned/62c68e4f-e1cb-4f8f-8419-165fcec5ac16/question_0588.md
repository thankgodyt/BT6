# Q588: era specific ledger data through hard fork wrappers in UpdateLedger

## Question
Can an unprivileged attacker reach UpdateLedger with era-specific ledger data through hard-fork wrappers and transaction witnesses, ledger state dependency, ticked ledger view, block application order, and era-specific ledger translation context, then confuse header/body, era, or storage context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/CommonProtocolParams.hs / UpdateLedger
- Entrypoint: Remote peer provides blocks/transactions that drive consensus ledger validation, replay, snapshots, or queries through normal node operation.
- Attacker controls: transaction witnesses, ledger state dependency, ticked ledger view, block application order, and era-specific ledger translation context.
- Exploit idea: Drive `UpdateLedger` in `Ouroboros.Consensus.Ledger.CommonProtocolParams` through the production entrypoint using era-specific ledger data through hard-fork wrappers; verify whether the path can confuse header/body, era, or storage context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Ledger tables, diffs, and derived views must remain equivalent between live validation, replay, and snapshot restoration.
- Expected Cardano/Intersect impact: Potential Critical if consensus accepts a block whose ledger transition is invalid under the selected state.
- Fast validation: Create a ledger integration property comparing consensus validation, direct ledger application, and replay from snapshot.
