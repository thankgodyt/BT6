# Q1902: era specific ledger data through hard fork wrappers in QueryEncoderException

## Question
Can an unprivileged attacker reach QueryEncoderException with era-specific ledger data through hard-fork wrappers and transaction witnesses, ledger state dependency, ticked ledger view, block application order, and era-specific ledger translation context, then confuse header/body, era, or storage context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Query.hs / QueryEncoderException
- Entrypoint: Remote peer provides blocks/transactions that drive consensus ledger validation, replay, snapshots, or queries through normal node operation.
- Attacker controls: transaction witnesses, ledger state dependency, ticked ledger view, block application order, and era-specific ledger translation context.
- Exploit idea: Drive `QueryEncoderException` in `Ouroboros.Consensus.Ledger.Query` through the production entrypoint using era-specific ledger data through hard-fork wrappers; verify whether the path can confuse header/body, era, or storage context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Ledger tables, diffs, and derived views must remain equivalent between live validation, replay, and snapshot restoration.
- Expected Cardano/Intersect impact: Potential High if snapshot/replay restores a ledger state inconsistent with the selected chain.
- Fast validation: Construct block-body transaction ordering tests and compare mempool acceptance against block application.
