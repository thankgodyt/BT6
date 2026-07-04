# Q3342: queries treated as current in fromMapInserts

## Question
Can an unprivileged attacker reach fromMapInserts with queries treated as current after chain selection changes and ledger tables, diffs, mempool transactions, snapshot selection, state-query target, and block validation timing, then reuse stale validation or ledger context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Tables/Diff.hs / fromMapInserts
- Entrypoint: Remote peer provides blocks/transactions that drive consensus ledger validation, replay, snapshots, or queries through normal node operation.
- Attacker controls: ledger tables, diffs, mempool transactions, snapshot selection, state-query target, and block validation timing.
- Exploit idea: Drive `fromMapInserts` in `Ouroboros.Consensus.Ledger.Tables.Diff` through the production entrypoint using queries treated as current after chain selection changes; verify whether the path can reuse stale validation or ledger context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A query or inspection path must not expose or use stale ledger state in a way that affects validation or block production.
- Expected Cardano/Intersect impact: Potential Critical if consensus accepts a block whose ledger transition is invalid under the selected state.
- Fast validation: Create a ledger integration property comparing consensus validation, direct ledger application, and replay from snapshot.
