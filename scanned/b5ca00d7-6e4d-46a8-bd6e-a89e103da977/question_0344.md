# Q344: an invalid descendant on an otherwise valid branch in FollowerHandle

## Question
Can an unprivileged attacker reach FollowerHandle with an invalid descendant on an otherwise valid branch and candidate fragment shape, rollback points, withheld bodies, stale blocks, competing branch timing, and peer disconnection timing, then starve a valid competing chain without prohibited flood-style DoS in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Types.hs / FollowerHandle
- Entrypoint: Remote peer sends adversarial but protocol-reachable ChainSync headers, BlockFetch bodies, duplicates, and rollbacks through normal node-to-node syncing.
- Attacker controls: candidate fragment shape, rollback points, withheld bodies, stale blocks, competing branch timing, and peer disconnection timing.
- Exploit idea: Drive `FollowerHandle` in `Ouroboros.Consensus.Storage.ChainDB.Impl.Types` through the production entrypoint using an invalid descendant on an otherwise valid branch; verify whether the path can starve a valid competing chain without prohibited flood-style DoS before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Invalid or unavailable block bodies must not permanently poison candidate selection or syncing progress.
- Expected Cardano/Intersect impact: Potential Medium if an unprivileged peer can cause sustained consensus/storage resource exhaustion through protocol-valid or near-valid data without prohibited flood-style DoS.
- Fast validation: Build a rollback/replay property comparing restored ledger state against fresh replay from the immutable anchor.
