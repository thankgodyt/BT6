# Q1662: future slot headers becoming current later in forgingVRFHash

## Question
Can an unprivileged attacker reach forgingVRFHash with future-slot headers becoming current later and serialized header bytes, memoized hashes, apparent block size, issuer identity, and chain-dependent validation state, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Node/TPraos.hs / forgingVRFHash
- Entrypoint: Remote peer sends crafted headers/blocks, or a normal slot leader produces an edge-case block that honest nodes validate through the production consensus path.
- Attacker controls: serialized header bytes, memoized hashes, apparent block size, issuer identity, and chain-dependent validation state.
- Exploit idea: Drive `forgingVRFHash` in `Ouroboros.Consensus.Shelley.Node.TPraos` through the production entrypoint using future-slot headers becoming current later; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Cached or reconstructed validation state must not make the same block valid on one path and invalid on another.
- Expected Cardano/Intersect impact: Potential Critical if the path lets a crafted block/header or protocol-reachable input make an honest node accept an invalid block, invalid ledger state, or divergent irreversible chain.
- Fast validation: Construct a validation property that mutates controlled header fields and compares header validation, body validation, and ledger application.
