# Q685: cached validation reused under another predecessor in convertPeriod

## Question
Can an unprivileged attacker reach convertPeriod with cached validation reused under another predecessor and serialized header bytes, memoized hashes, apparent block size, issuer identity, and chain-dependent validation state, then starve a valid competing chain without prohibited flood-style DoS in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos/AgentClient.hs / convertPeriod
- Entrypoint: Remote peer sends crafted headers/blocks, or a normal slot leader produces an edge-case block that honest nodes validate through the production consensus path.
- Attacker controls: serialized header bytes, memoized hashes, apparent block size, issuer identity, and chain-dependent validation state.
- Exploit idea: Drive `convertPeriod` in `Ouroboros.Consensus.Protocol.Praos.AgentClient` through the production entrypoint using cached validation reused under another predecessor; verify whether the path can starve a valid competing chain without prohibited flood-style DoS before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Cached or reconstructed validation state must not make the same block valid on one path and invalid on another.
- Expected Cardano/Intersect impact: Potential Critical if the path bypasses leader eligibility, VRF/KES/certificate/signature, PBFT/Praos/TPraos/Peras, or hot-key validation and accepts unauthorized consensus data.
- Fast validation: Add a protocol unit test around boundary slots and assert invalid issuer/VRF/KES/certificate data is rejected before state update.
