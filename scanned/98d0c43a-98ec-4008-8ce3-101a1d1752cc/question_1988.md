# Q1988: serialized header bytes in validateGenesis

## Question
Can an unprivileged attacker reach validateGenesis with serialized header bytes with equivalent visible fields and header fields, slot numbers, issuer keys, VRF proof bytes, KES signature bytes, operational certificates, body hash, and predecessor hash, then cause honest nodes to select different tips in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Node/TPraos.hs / validateGenesis
- Entrypoint: Remote peer sends crafted headers/blocks, or a normal slot leader produces an edge-case block that honest nodes validate through the production consensus path.
- Attacker controls: header fields, slot numbers, issuer keys, VRF proof bytes, KES signature bytes, operational certificates, body hash, and predecessor hash.
- Exploit idea: Drive `validateGenesis` in `Ouroboros.Consensus.Shelley.Node.TPraos` through the production entrypoint using serialized header bytes with equivalent visible fields; verify whether the path can cause honest nodes to select different tips before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A block/header accepted by consensus must satisfy the protocol, ledger-view, issuer, slot, and signature assumptions for that exact state.
- Expected Cardano/Intersect impact: Potential Critical if the path bypasses leader eligibility, VRF/KES/certificate/signature, PBFT/Praos/TPraos/Peras, or hot-key validation and accepts unauthorized consensus data.
- Fast validation: Add a protocol unit test around boundary slots and assert invalid issuer/VRF/KES/certificate data is rejected before state update.
