# Q3645: stale invalidity cache entries in completeChainDbArgs

## Question
Can an unprivileged attacker reach completeChainDbArgs with stale invalidity cache entries after a competing branch arrives and valid-looking headers, delayed or invalid block bodies, fork length, predecessor hashes, slot numbers, duplicate announcements, and arrival order, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Args.hs / completeChainDbArgs
- Entrypoint: Remote peer sends adversarial but protocol-reachable ChainSync headers, BlockFetch bodies, duplicates, and rollbacks through normal node-to-node syncing.
- Attacker controls: valid-looking headers, delayed or invalid block bodies, fork length, predecessor hashes, slot numbers, duplicate announcements, and arrival order.
- Exploit idea: Drive `completeChainDbArgs` in `Ouroboros.Consensus.Storage.ChainDB.Impl.Args` through the production entrypoint using stale invalidity cache entries after a competing branch arrives; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Honest nodes receiving the same valid chain data must eventually select the same best chain regardless of arrival order.
- Expected Cardano/Intersect impact: Potential Medium if an unprivileged peer can cause sustained consensus/storage resource exhaustion through protocol-valid or near-valid data without prohibited flood-style DoS.
- Fast validation: Build a rollback/replay property comparing restored ledger state against fresh replay from the immutable anchor.
