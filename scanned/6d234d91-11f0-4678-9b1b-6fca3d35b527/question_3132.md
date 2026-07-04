# Q3132: a candidate crossing the volatile to immutable boundary in applyAcrossEraMode

## Question
Can an unprivileged attacker reach applyAcrossEraMode with a candidate crossing the volatile-to-immutable boundary and fork density, chain fragment ancestry, invalid descendant timing, validation cache pressure, and restart boundary timing, then confuse header/body, era, or storage context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Protocol/ChainSel.hs / applyAcrossEraMode
- Entrypoint: Remote peer sends adversarial but protocol-reachable ChainSync headers, BlockFetch bodies, duplicates, and rollbacks through normal node-to-node syncing.
- Attacker controls: fork density, chain fragment ancestry, invalid descendant timing, validation cache pressure, and restart boundary timing.
- Exploit idea: Drive `applyAcrossEraMode` in `Ouroboros.Consensus.HardFork.Combinator.Protocol.ChainSel` through the production entrypoint using a candidate crossing the volatile-to-immutable boundary; verify whether the path can confuse header/body, era, or storage context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A candidate fragment must not become preferred unless every required predecessor and validation result is consistent.
- Expected Cardano/Intersect impact: Potential Medium if an unprivileged peer can cause sustained consensus/storage resource exhaustion through protocol-valid or near-valid data without prohibited flood-style DoS.
- Fast validation: Build a rollback/replay property comparing restored ledger state against fresh replay from the immutable anchor.
