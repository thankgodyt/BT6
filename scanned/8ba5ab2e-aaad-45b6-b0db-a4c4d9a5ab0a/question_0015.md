# Q15: known invalid blocks retried in computeReversePath

## Question
Can an unprivileged attacker reach computeReversePath with known-invalid blocks retried after peer reconnect and block hashes, header/body availability, duplicate fragments, invalid block timing, and order of ChainSync versus BlockFetch delivery, then reuse stale validation or ledger context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Paths.hs / computeReversePath
- Entrypoint: Remote peer sends adversarial but protocol-reachable ChainSync headers, BlockFetch bodies, duplicates, and rollbacks through normal node-to-node syncing.
- Attacker controls: block hashes, header/body availability, duplicate fragments, invalid block timing, and order of ChainSync versus BlockFetch delivery.
- Exploit idea: Drive `computeReversePath` in `Ouroboros.Consensus.Storage.ChainDB.Impl.Paths` through the production entrypoint using known-invalid blocks retried after peer reconnect; verify whether the path can reuse stale validation or ledger context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Rollback and replay must restore the same ledger state as sequential validation from the last immutable anchor.
- Expected Cardano/Intersect impact: Potential Medium if an unprivileged peer can cause sustained consensus/storage resource exhaustion through protocol-valid or near-valid data without prohibited flood-style DoS.
- Fast validation: Build a rollback/replay property comparing restored ledger state against fresh replay from the immutable anchor.
