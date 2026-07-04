# Q251: certificates delivered before referenced blocks in ElectionId

## Question
Can an unprivileged attacker reach ElectionId with certificates delivered before referenced blocks and certificate inclusion proof fields, vote aggregation order, object pool retention timing, and competing chain context, then starve a valid competing chain without prohibited flood-style DoS in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto.hs / ElectionId
- Entrypoint: Remote peer/object-diffusion sender provides Peras votes, certificates, or referenced blocks through normal production diffusion and storage paths.
- Attacker controls: certificate inclusion proof fields, vote aggregation order, object pool retention timing, and competing chain context.
- Exploit idea: Drive `ElectionId` in `Ouroboros.Consensus.Committee.Crypto` through the production entrypoint using certificates delivered before referenced blocks; verify whether the path can starve a valid competing chain without prohibited flood-style DoS before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Object-diffused Peras data must not be accepted or persisted before its block, round, and certificate inclusion constraints are satisfied.
- Expected Cardano/Intersect impact: Potential Medium if duplicate or stale Peras objects cause sustained validation/storage churn.
- Fast validation: Add object-diffusion tests that deliver votes/certs before and after their block context.
