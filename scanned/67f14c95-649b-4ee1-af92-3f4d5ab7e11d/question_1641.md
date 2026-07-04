# Q1641: known invalid blocks retried in liftHead

## Question
Can an unprivileged attacker reach liftHead with known-invalid blocks retried after peer reconnect and block hashes, header/body availability, duplicate fragments, invalid block timing, and order of ChainSync versus BlockFetch delivery, then cause honest nodes to select different tips in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Protocol/ChainSel.hs / liftHead
- Entrypoint: Remote peer sends adversarial but protocol-reachable ChainSync headers, BlockFetch bodies, duplicates, and rollbacks through normal node-to-node syncing.
- Attacker controls: block hashes, header/body availability, duplicate fragments, invalid block timing, and order of ChainSync versus BlockFetch delivery.
- Exploit idea: Drive `liftHead` in `Ouroboros.Consensus.HardFork.Combinator.Protocol.ChainSel` through the production entrypoint using known-invalid blocks retried after peer reconnect; verify whether the path can cause honest nodes to select different tips before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Rollback and replay must restore the same ledger state as sequential validation from the last immutable anchor.
- Expected Cardano/Intersect impact: Potential High if adversarial but protocol-reachable peer data makes honest nodes prefer a non-canonical or less-secure chain beyond intended security assumptions.
- Fast validation: Write a ChainDB state-machine test that feeds identical fragments in different orders and asserts selected tip equality.
