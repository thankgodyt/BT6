# Q3141: candidate switching while cleanup is eligible in implIteratorNext

## Question
Can an unprivileged attacker reach implIteratorNext with candidate switching while cleanup is eligible and fork density, chain fragment ancestry, invalid descendant timing, validation cache pressure, and restart boundary timing, then starve a valid competing chain without prohibited flood-style DoS in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Iterator.hs / implIteratorNext
- Entrypoint: Remote peer sends adversarial but protocol-reachable ChainSync headers, BlockFetch bodies, duplicates, and rollbacks through normal node-to-node syncing.
- Attacker controls: fork density, chain fragment ancestry, invalid descendant timing, validation cache pressure, and restart boundary timing.
- Exploit idea: Drive `implIteratorNext` in `Ouroboros.Consensus.Storage.ChainDB.Impl.Iterator` through the production entrypoint using candidate switching while cleanup is eligible; verify whether the path can starve a valid competing chain without prohibited flood-style DoS before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A candidate fragment must not become preferred unless every required predecessor and validation result is consistent.
- Expected Cardano/Intersect impact: Potential Medium if an unprivileged peer can cause sustained consensus/storage resource exhaustion through protocol-valid or near-valid data without prohibited flood-style DoS.
- Fast validation: Build a rollback/replay property comparing restored ledger state against fresh replay from the immutable anchor.
