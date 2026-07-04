# Q3664: a block validated in PraosTiebreakerView

## Question
Can an unprivileged attacker reach PraosTiebreakerView with a block validated after rollback with stale ledger view and future/past slot edges, leadership evidence, delegation state references, signature encodings, and validation-cache entry ordering, then make a valid block permanently or durably rejected in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos/Common.hs / PraosTiebreakerView
- Entrypoint: Remote peer sends crafted headers/blocks, or a normal slot leader produces an edge-case block that honest nodes validate through the production consensus path.
- Attacker controls: future/past slot edges, leadership evidence, delegation state references, signature encodings, and validation-cache entry ordering.
- Exploit idea: Drive `PraosTiebreakerView` in `Ouroboros.Consensus.Protocol.Praos.Common` through the production entrypoint using a block validated after rollback with stale ledger view; verify whether the path can make a valid block permanently or durably rejected before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Leader eligibility, VRF, KES, operational certificate, and delegation checks must not be bypassed by malformed edge fields.
- Expected Cardano/Intersect impact: Potential Critical if the path lets a crafted block/header or protocol-reachable input make an honest node accept an invalid block, invalid ledger state, or divergent irreversible chain.
- Fast validation: Construct a validation property that mutates controlled header fields and compares header validation, body validation, and ledger application.
