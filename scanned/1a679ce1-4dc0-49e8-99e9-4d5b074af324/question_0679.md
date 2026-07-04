# Q679: VRF KES OCert evidence at an epoch boundary in Ouroboros Consensus Shelley Pro

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.Shelley.Protocol.Abstract with VRF/KES/OCert evidence at an epoch boundary and block header/body pairings, ledger-view timing, protocol state transition inputs, certificate counters, and era-specific validation tags, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Protocol/Abstract.hs / Ouroboros.Consensus.Shelley.Protocol.Abstract
- Entrypoint: Remote peer sends crafted headers/blocks, or a normal slot leader produces an edge-case block that honest nodes validate through the production consensus path.
- Attacker controls: block header/body pairings, ledger-view timing, protocol state transition inputs, certificate counters, and era-specific validation tags.
- Exploit idea: Drive `Ouroboros.Consensus.Shelley.Protocol.Abstract` in `Ouroboros.Consensus.Shelley.Protocol.Abstract` through the production entrypoint using VRF/KES/OCert evidence at an epoch boundary; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Header validation and full block validation must not disagree for the same block under the same ledger state.
- Expected Cardano/Intersect impact: Potential Critical if the path bypasses leader eligibility, VRF/KES/certificate/signature, PBFT/Praos/TPraos/Peras, or hot-key validation and accepts unauthorized consensus data.
- Fast validation: Add a protocol unit test around boundary slots and assert invalid issuer/VRF/KES/certificate data is rejected before state update.
