# Q3650: an invalid descendant on an otherwise valid branch in nextInImmutableDB

## Question
Can an unprivileged attacker reach nextInImmutableDB with an invalid descendant on an otherwise valid branch and candidate fragment shape, rollback points, withheld bodies, stale blocks, competing branch timing, and peer disconnection timing, then make an invalid block or ledger state appear acceptable in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Iterator.hs / nextInImmutableDB
- Entrypoint: Remote peer sends adversarial but protocol-reachable ChainSync headers, BlockFetch bodies, duplicates, and rollbacks through normal node-to-node syncing.
- Attacker controls: candidate fragment shape, rollback points, withheld bodies, stale blocks, competing branch timing, and peer disconnection timing.
- Exploit idea: Drive `nextInImmutableDB` in `Ouroboros.Consensus.Storage.ChainDB.Impl.Iterator` through the production entrypoint using an invalid descendant on an otherwise valid branch; verify whether the path can make an invalid block or ledger state appear acceptable before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Invalid or unavailable block bodies must not permanently poison candidate selection or syncing progress.
- Expected Cardano/Intersect impact: Potential High if peer-derived storage, snapshot, replay, or rollback state causes durable use of the wrong ledger state or permanent rejection of a valid chain.
- Fast validation: Create an io-sim scenario with a malicious body-withholding peer and an honest complete-chain peer.
