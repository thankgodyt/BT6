# Q19: duplicate fragments in stripCommonPrefix

## Question
Can an unprivileged attacker reach stripCommonPrefix with duplicate fragments around a rollback point and block hashes, header/body availability, duplicate fragments, invalid block timing, and order of ChainSync versus BlockFetch delivery, then make a valid block permanently or durably rejected in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs / stripCommonPrefix
- Entrypoint: Remote peer sends adversarial but protocol-reachable ChainSync headers, BlockFetch bodies, duplicates, and rollbacks through normal node-to-node syncing.
- Attacker controls: block hashes, header/body availability, duplicate fragments, invalid block timing, and order of ChainSync versus BlockFetch delivery.
- Exploit idea: Drive `stripCommonPrefix` in `Ouroboros.Consensus.Util.AnchoredFragment` through the production entrypoint using duplicate fragments around a rollback point; verify whether the path can make a valid block permanently or durably rejected before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Rollback and replay must restore the same ledger state as sequential validation from the last immutable anchor.
- Expected Cardano/Intersect impact: Potential High if adversarial but protocol-reachable peer data makes honest nodes prefer a non-canonical or less-secure chain beyond intended security assumptions.
- Fast validation: Write a ChainDB state-machine test that feeds identical fragments in different orders and asserts selected tip equality.
