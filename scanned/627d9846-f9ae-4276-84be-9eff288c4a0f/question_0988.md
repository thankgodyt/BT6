# Q988: candidate switching while cleanup is eligible in Ouroboros Consensus Storage C

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.Storage.ChainDB with candidate switching while cleanup is eligible and fork density, chain fragment ancestry, invalid descendant timing, validation cache pressure, and restart boundary timing, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB.hs / Ouroboros.Consensus.Storage.ChainDB
- Entrypoint: Remote peer sends adversarial but protocol-reachable ChainSync headers, BlockFetch bodies, duplicates, and rollbacks through normal node-to-node syncing.
- Attacker controls: fork density, chain fragment ancestry, invalid descendant timing, validation cache pressure, and restart boundary timing.
- Exploit idea: Drive `Ouroboros.Consensus.Storage.ChainDB` in `Ouroboros.Consensus.Storage.ChainDB` through the production entrypoint using candidate switching while cleanup is eligible; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A candidate fragment must not become preferred unless every required predecessor and validation result is consistent.
- Expected Cardano/Intersect impact: Potential High if peer-derived storage, snapshot, replay, or rollback state causes durable use of the wrong ledger state or permanent rejection of a valid chain.
- Fast validation: Create an io-sim scenario with a malicious body-withholding peer and an honest complete-chain peer.
