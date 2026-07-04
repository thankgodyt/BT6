# Q3672: a block validated in BftValidationErr

## Question
Can an unprivileged attacker reach BftValidationErr with a block validated after rollback with stale ledger view and future/past slot edges, leadership evidence, delegation state references, signature encodings, and validation-cache entry ordering, then make a valid block permanently or durably rejected in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/BFT.hs / BftValidationErr
- Entrypoint: Remote peer sends crafted headers/blocks, or a normal slot leader produces an edge-case block that honest nodes validate through the production consensus path.
- Attacker controls: future/past slot edges, leadership evidence, delegation state references, signature encodings, and validation-cache entry ordering.
- Exploit idea: Drive `BftValidationErr` in `Ouroboros.Consensus.Protocol.BFT` through the production entrypoint using a block validated after rollback with stale ledger view; verify whether the path can make a valid block permanently or durably rejected before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Leader eligibility, VRF, KES, operational certificate, and delegation checks must not be bypassed by malformed edge fields.
- Expected Cardano/Intersect impact: Potential High if adversarial but protocol-reachable peer data makes honest nodes prefer a non-canonical or less-secure chain beyond intended security assumptions.
- Fast validation: Fuzz serialized headers and body-hash mismatches while asserting no cached-valid reuse across predecessor contexts.
