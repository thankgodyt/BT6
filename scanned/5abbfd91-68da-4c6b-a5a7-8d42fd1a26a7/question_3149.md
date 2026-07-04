# Q3149: a block validated in Signed

## Question
Can an unprivileged attacker reach Signed with a block validated after rollback with stale ledger view and future/past slot edges, leadership evidence, delegation state references, signature encodings, and validation-cache entry ordering, then reuse stale validation or ledger context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Protocol/Praos.hs / Signed
- Entrypoint: Remote peer sends crafted headers/blocks, or a normal slot leader produces an edge-case block that honest nodes validate through the production consensus path.
- Attacker controls: future/past slot edges, leadership evidence, delegation state references, signature encodings, and validation-cache entry ordering.
- Exploit idea: Drive `Signed` in `Ouroboros.Consensus.Shelley.Protocol.Praos` through the production entrypoint using a block validated after rollback with stale ledger view; verify whether the path can reuse stale validation or ledger context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Leader eligibility, VRF, KES, operational certificate, and delegation checks must not be bypassed by malformed edge fields.
- Expected Cardano/Intersect impact: Potential Critical if the path bypasses leader eligibility, VRF/KES/certificate/signature, PBFT/Praos/TPraos/Peras, or hot-key validation and accepts unauthorized consensus data.
- Fast validation: Add a protocol unit test around boundary slots and assert invalid issuer/VRF/KES/certificate data is rejected before state update.
