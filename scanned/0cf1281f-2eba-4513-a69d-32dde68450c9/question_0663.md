# Q663: an invalid descendant on an otherwise valid branch in Ouroboros Consensus Stor

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.Storage.ChainDB.Impl with an invalid descendant on an otherwise valid branch and candidate fragment shape, rollback points, withheld bodies, stale blocks, competing branch timing, and peer disconnection timing, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl.hs / Ouroboros.Consensus.Storage.ChainDB.Impl
- Entrypoint: Remote peer sends adversarial but protocol-reachable ChainSync headers, BlockFetch bodies, duplicates, and rollbacks through normal node-to-node syncing.
- Attacker controls: candidate fragment shape, rollback points, withheld bodies, stale blocks, competing branch timing, and peer disconnection timing.
- Exploit idea: Drive `Ouroboros.Consensus.Storage.ChainDB.Impl` in `Ouroboros.Consensus.Storage.ChainDB.Impl` through the production entrypoint using an invalid descendant on an otherwise valid branch; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Invalid or unavailable block bodies must not permanently poison candidate selection or syncing progress.
- Expected Cardano/Intersect impact: Potential High if adversarial but protocol-reachable peer data makes honest nodes prefer a non-canonical or less-secure chain beyond intended security assumptions.
- Fast validation: Write a ChainDB state-machine test that feeds identical fragments in different orders and asserts selected tip equality.
