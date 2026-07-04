# Q1904: ledger error wrapping that hides fatal validation failure in txInvariant

## Question
Can an unprivileged attacker reach txInvariant with ledger error wrapping that hides fatal validation failure and serialized ledger-related data, block body size, transaction ordering, replayed blocks, and forecast-derived ledger view, then make an invalid block or ledger state appear acceptable in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/SupportsMempool.hs / txInvariant
- Entrypoint: Remote peer provides blocks/transactions that drive consensus ledger validation, replay, snapshots, or queries through normal node operation.
- Attacker controls: serialized ledger-related data, block body size, transaction ordering, replayed blocks, and forecast-derived ledger view.
- Exploit idea: Drive `txInvariant` in `Ouroboros.Consensus.Ledger.SupportsMempool` through the production entrypoint using ledger error wrapping that hides fatal validation failure; verify whether the path can make an invalid block or ledger state appear acceptable before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Consensus and ledger validity must remain deterministic for the same block and predecessor chain.
- Expected Cardano/Intersect impact: Potential High if ledger view or table mismatch makes honest nodes validate the same chain differently.
- Fast validation: Build a rollback/replay test over ledger tables and assert table hashes match fresh sequential validation.
