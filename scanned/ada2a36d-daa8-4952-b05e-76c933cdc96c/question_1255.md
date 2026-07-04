# Q1255: queries treated as current in LedgerTableConstraints

## Question
Can an unprivileged attacker reach LedgerTableConstraints with queries treated as current after chain selection changes and ledger tables, diffs, mempool transactions, snapshot selection, state-query target, and block validation timing, then cause honest nodes to select different tips in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Tables/Combinators.hs / LedgerTableConstraints
- Entrypoint: Remote peer provides blocks/transactions that drive consensus ledger validation, replay, snapshots, or queries through normal node operation.
- Attacker controls: ledger tables, diffs, mempool transactions, snapshot selection, state-query target, and block validation timing.
- Exploit idea: Drive `LedgerTableConstraints` in `Ouroboros.Consensus.Ledger.Tables.Combinators` through the production entrypoint using queries treated as current after chain selection changes; verify whether the path can cause honest nodes to select different tips before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A query or inspection path must not expose or use stale ledger state in a way that affects validation or block production.
- Expected Cardano/Intersect impact: Potential High if ledger view or table mismatch makes honest nodes validate the same chain differently.
- Fast validation: Build a rollback/replay test over ledger tables and assert table hashes match fresh sequential validation.
