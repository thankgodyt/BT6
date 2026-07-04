# Q3137: a candidate crossing the volatile to immutable boundary in GcParams

## Question
Can an unprivileged attacker reach GcParams with a candidate crossing the volatile-to-immutable boundary and fork density, chain fragment ancestry, invalid descendant timing, validation cache pressure, and restart boundary timing, then confuse header/body, era, or storage context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Background.hs / GcParams
- Entrypoint: Remote peer sends adversarial but protocol-reachable ChainSync headers, BlockFetch bodies, duplicates, and rollbacks through normal node-to-node syncing.
- Attacker controls: fork density, chain fragment ancestry, invalid descendant timing, validation cache pressure, and restart boundary timing.
- Exploit idea: Drive `GcParams` in `Ouroboros.Consensus.Storage.ChainDB.Impl.Background` through the production entrypoint using a candidate crossing the volatile-to-immutable boundary; verify whether the path can confuse header/body, era, or storage context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A candidate fragment must not become preferred unless every required predecessor and validation result is consistent.
- Expected Cardano/Intersect impact: Potential High if peer-derived storage, snapshot, replay, or rollback state causes durable use of the wrong ledger state or permanent rejection of a valid chain.
- Fast validation: Create an io-sim scenario with a malicious body-withholding peer and an honest complete-chain peer.
