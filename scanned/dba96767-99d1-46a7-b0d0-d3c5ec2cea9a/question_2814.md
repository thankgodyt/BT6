# Q2814: object pool retention across rollback in signWithRole

## Question
Can an unprivileged attacker reach signWithRole with object-pool retention across rollback and votes, certificates, rounds, block references, committee member identifiers, weights, duplicate object-diffusion items, and stale inclusion evidence, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs / signWithRole
- Entrypoint: Remote peer/object-diffusion sender provides Peras votes, certificates, or referenced blocks through normal production diffusion and storage paths.
- Attacker controls: votes, certificates, rounds, block references, committee member identifiers, weights, duplicate object-diffusion items, and stale inclusion evidence.
- Exploit idea: Drive `signWithRole` in `Ouroboros.Consensus.Committee.Crypto.BLS` through the production entrypoint using object-pool retention across rollback; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Peras votes, certificates, committee weights, and selection views must not change chain preference unless their verification assumptions hold.
- Expected Cardano/Intersect impact: Potential Medium if duplicate or stale Peras objects cause sustained validation/storage churn.
- Fast validation: Add object-diffusion tests that deliver votes/certs before and after their block context.
