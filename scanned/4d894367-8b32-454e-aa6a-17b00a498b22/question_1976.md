# Q1976: headers for a preferred candidate whose bodies arrive late in cacheBlock

## Question
Can an unprivileged attacker reach cacheBlock with headers for a preferred candidate whose bodies arrive late and valid-looking headers, delayed or invalid block bodies, fork length, predecessor hashes, slot numbers, duplicate announcements, and arrival order, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/BlockCache.hs / cacheBlock
- Entrypoint: Remote peer sends adversarial but protocol-reachable ChainSync headers, BlockFetch bodies, duplicates, and rollbacks through normal node-to-node syncing.
- Attacker controls: valid-looking headers, delayed or invalid block bodies, fork length, predecessor hashes, slot numbers, duplicate announcements, and arrival order.
- Exploit idea: Drive `cacheBlock` in `Ouroboros.Consensus.Storage.ChainDB.Impl.BlockCache` through the production entrypoint using headers for a preferred candidate whose bodies arrive late; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Honest nodes receiving the same valid chain data must eventually select the same best chain regardless of arrival order.
- Expected Cardano/Intersect impact: Potential High if peer-derived storage, snapshot, replay, or rollback state causes durable use of the wrong ledger state or permanent rejection of a valid chain.
- Fast validation: Create an io-sim scenario with a malicious body-withholding peer and an honest complete-chain peer.
