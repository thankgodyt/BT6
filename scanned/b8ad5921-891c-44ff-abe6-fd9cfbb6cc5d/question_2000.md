# Q2000: a header accepted before the body hash is checked in IsLeader

## Question
Can an unprivileged attacker reach IsLeader with a header accepted before the body hash is checked and header fields, slot numbers, issuer keys, VRF proof bytes, KES signature bytes, operational certificates, body hash, and predecessor hash, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/TPraos.hs / IsLeader
- Entrypoint: Remote peer sends crafted headers/blocks, or a normal slot leader produces an edge-case block that honest nodes validate through the production consensus path.
- Attacker controls: header fields, slot numbers, issuer keys, VRF proof bytes, KES signature bytes, operational certificates, body hash, and predecessor hash.
- Exploit idea: Drive `IsLeader` in `Ouroboros.Consensus.Protocol.TPraos` through the production entrypoint using a header accepted before the body hash is checked; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A block/header accepted by consensus must satisfy the protocol, ledger-view, issuer, slot, and signature assumptions for that exact state.
- Expected Cardano/Intersect impact: Potential Critical if the path bypasses leader eligibility, VRF/KES/certificate/signature, PBFT/Praos/TPraos/Peras, or hot-key validation and accepts unauthorized consensus data.
- Fast validation: Add a protocol unit test around boundary slots and assert invalid issuer/VRF/KES/certificate data is rejected before state update.
