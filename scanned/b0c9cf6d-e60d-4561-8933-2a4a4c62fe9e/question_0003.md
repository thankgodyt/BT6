# Q3: duplicate fragments in selectPreferredCandidate

## Question
Can an unprivileged attacker reach selectPreferredCandidate with duplicate fragments around a rollback point and block hashes, header/body availability, duplicate fragments, invalid block timing, and order of ChainSync versus BlockFetch delivery, then make a valid block permanently or durably rejected in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/MockChainSel.hs / selectPreferredCandidate
- Entrypoint: Remote peer sends adversarial but protocol-reachable ChainSync headers, BlockFetch bodies, duplicates, and rollbacks through normal node-to-node syncing.
- Attacker controls: block hashes, header/body availability, duplicate fragments, invalid block timing, and order of ChainSync versus BlockFetch delivery.
- Exploit idea: Drive `selectPreferredCandidate` in `Ouroboros.Consensus.Protocol.MockChainSel` through the production entrypoint using duplicate fragments around a rollback point; verify whether the path can make a valid block permanently or durably rejected before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Rollback and replay must restore the same ledger state as sequential validation from the last immutable anchor.
- Expected Cardano/Intersect impact: Potential Medium if an unprivileged peer can cause sustained consensus/storage resource exhaustion through protocol-valid or near-valid data without prohibited flood-style DoS.
- Fast validation: Build a rollback/replay property comparing restored ledger state against fresh replay from the immutable anchor.
