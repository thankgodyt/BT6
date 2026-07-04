# Q2218: object pool retention across rollback in Ouroboros Consensus Committee LS

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.Committee.LS with object-pool retention across rollback and votes, certificates, rounds, block references, committee member identifiers, weights, duplicate object-diffusion items, and stale inclusion evidence, then cause honest nodes to select different tips in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/LS.hs / Ouroboros.Consensus.Committee.LS
- Entrypoint: Remote peer/object-diffusion sender provides Peras votes, certificates, or referenced blocks through normal production diffusion and storage paths.
- Attacker controls: votes, certificates, rounds, block references, committee member identifiers, weights, duplicate object-diffusion items, and stale inclusion evidence.
- Exploit idea: Drive `Ouroboros.Consensus.Committee.LS` in `Ouroboros.Consensus.Committee.LS` through the production entrypoint using object-pool retention across rollback; verify whether the path can cause honest nodes to select different tips before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Peras votes, certificates, committee weights, and selection views must not change chain preference unless their verification assumptions hold.
- Expected Cardano/Intersect impact: Potential Medium if duplicate or stale Peras objects cause sustained validation/storage churn.
- Fast validation: Add object-diffusion tests that deliver votes/certs before and after their block context.
