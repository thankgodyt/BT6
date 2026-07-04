# Q2229: ledger error wrapping that hides fatal validation failure in QueryVersion

## Question
Can an unprivileged attacker reach QueryVersion with ledger error wrapping that hides fatal validation failure and serialized ledger-related data, block body size, transaction ordering, replayed blocks, and forecast-derived ledger view, then starve a valid competing chain without prohibited flood-style DoS in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Query/Version.hs / QueryVersion
- Entrypoint: Remote peer provides blocks/transactions that drive consensus ledger validation, replay, snapshots, or queries through normal node operation.
- Attacker controls: serialized ledger-related data, block body size, transaction ordering, replayed blocks, and forecast-derived ledger view.
- Exploit idea: Drive `QueryVersion` in `Ouroboros.Consensus.Ledger.Query.Version` through the production entrypoint using ledger error wrapping that hides fatal validation failure; verify whether the path can starve a valid competing chain without prohibited flood-style DoS before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Consensus and ledger validity must remain deterministic for the same block and predecessor chain.
- Expected Cardano/Intersect impact: Potential High if ledger view or table mismatch makes honest nodes validate the same chain differently.
- Fast validation: Build a rollback/replay test over ledger tables and assert table hashes match fresh sequential validation.
