# Q357: delegation or certificate counter boundary values in convertOCert

## Question
Can an unprivileged attacker reach convertOCert with delegation or certificate counter boundary values and future/past slot edges, leadership evidence, delegation state references, signature encodings, and validation-cache entry ordering, then cause honest nodes to select different tips in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos/AgentClient.hs / convertOCert
- Entrypoint: Remote peer sends crafted headers/blocks, or a normal slot leader produces an edge-case block that honest nodes validate through the production consensus path.
- Attacker controls: future/past slot edges, leadership evidence, delegation state references, signature encodings, and validation-cache entry ordering.
- Exploit idea: Drive `convertOCert` in `Ouroboros.Consensus.Protocol.Praos.AgentClient` through the production entrypoint using delegation or certificate counter boundary values; verify whether the path can cause honest nodes to select different tips before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Leader eligibility, VRF, KES, operational certificate, and delegation checks must not be bypassed by malformed edge fields.
- Expected Cardano/Intersect impact: Potential Critical if the path lets a crafted block/header or protocol-reachable input make an honest node accept an invalid block, invalid ledger state, or divergent irreversible chain.
- Fast validation: Construct a validation property that mutates controlled header fields and compares header validation, body validation, and ledger application.
