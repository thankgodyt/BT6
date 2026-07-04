# Q3143: an invalid descendant on an otherwise valid branch in getPerasVotesAfter

## Question
Can an unprivileged attacker reach getPerasVotesAfter with an invalid descendant on an otherwise valid branch and candidate fragment shape, rollback points, withheld bodies, stale blocks, competing branch timing, and peer disconnection timing, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Query.hs / getPerasVotesAfter
- Entrypoint: Remote peer sends adversarial but protocol-reachable ChainSync headers, BlockFetch bodies, duplicates, and rollbacks through normal node-to-node syncing.
- Attacker controls: candidate fragment shape, rollback points, withheld bodies, stale blocks, competing branch timing, and peer disconnection timing.
- Exploit idea: Drive `getPerasVotesAfter` in `Ouroboros.Consensus.Storage.ChainDB.Impl.Query` through the production entrypoint using an invalid descendant on an otherwise valid branch; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Invalid or unavailable block bodies must not permanently poison candidate selection or syncing progress.
- Expected Cardano/Intersect impact: Potential High if peer-derived storage, snapshot, replay, or rollback state causes durable use of the wrong ledger state or permanent rejection of a valid chain.
- Fast validation: Create an io-sim scenario with a malicious body-withholding peer and an honest complete-chain peer.
