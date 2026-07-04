# Q992: a candidate crossing the volatile to immutable boundary in enableLedgerEvents

## Question
Can an unprivileged attacker reach enableLedgerEvents with a candidate crossing the volatile-to-immutable boundary and fork density, chain fragment ancestry, invalid descendant timing, validation cache pressure, and restart boundary timing, then make an invalid block or ledger state appear acceptable in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Args.hs / enableLedgerEvents
- Entrypoint: Remote peer sends adversarial but protocol-reachable ChainSync headers, BlockFetch bodies, duplicates, and rollbacks through normal node-to-node syncing.
- Attacker controls: fork density, chain fragment ancestry, invalid descendant timing, validation cache pressure, and restart boundary timing.
- Exploit idea: Drive `enableLedgerEvents` in `Ouroboros.Consensus.Storage.ChainDB.Impl.Args` through the production entrypoint using a candidate crossing the volatile-to-immutable boundary; verify whether the path can make an invalid block or ledger state appear acceptable before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A candidate fragment must not become preferred unless every required predecessor and validation result is consistent.
- Expected Cardano/Intersect impact: Potential Medium if an unprivileged peer can cause sustained consensus/storage resource exhaustion through protocol-valid or near-valid data without prohibited flood-style DoS.
- Fast validation: Build a rollback/replay property comparing restored ledger state against fresh replay from the immutable anchor.
