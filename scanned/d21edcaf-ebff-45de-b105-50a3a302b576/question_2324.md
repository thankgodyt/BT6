# Q2324: cached validation reused under another predecessor in VRFUsage

## Question
Can an unprivileged attacker reach VRFUsage with cached validation reused under another predecessor and serialized header bytes, memoized hashes, apparent block size, issuer identity, and chain-dependent validation state, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos/VRF.hs / VRFUsage
- Entrypoint: Remote peer sends crafted headers/blocks, or a normal slot leader produces an edge-case block that honest nodes validate through the production consensus path.
- Attacker controls: serialized header bytes, memoized hashes, apparent block size, issuer identity, and chain-dependent validation state.
- Exploit idea: Drive `VRFUsage` in `Ouroboros.Consensus.Protocol.Praos.VRF` through the production entrypoint using cached validation reused under another predecessor; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Cached or reconstructed validation state must not make the same block valid on one path and invalid on another.
- Expected Cardano/Intersect impact: Potential Critical if the path lets a crafted block/header or protocol-reachable input make an honest node accept an invalid block, invalid ledger state, or divergent irreversible chain.
- Fast validation: Construct a validation property that mutates controlled header fields and compares header validation, body validation, and ledger application.
