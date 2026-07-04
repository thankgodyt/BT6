# Q3579: Peras weight conflicting in verifyProofOfPossession

## Question
Can an unprivileged attacker reach verifyProofOfPossession with Peras weight conflicting with Praos chain order and certificate inclusion proof fields, vote aggregation order, object pool retention timing, and competing chain context, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs / verifyProofOfPossession
- Entrypoint: Remote peer/object-diffusion sender provides Peras votes, certificates, or referenced blocks through normal production diffusion and storage paths.
- Attacker controls: certificate inclusion proof fields, vote aggregation order, object pool retention timing, and competing chain context.
- Exploit idea: Drive `verifyProofOfPossession` in `Ouroboros.Consensus.Committee.Crypto.BLS` through the production entrypoint using Peras weight conflicting with Praos chain order; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Object-diffused Peras data must not be accepted or persisted before its block, round, and certificate inclusion constraints are satisfied.
- Expected Cardano/Intersect impact: Potential Medium if duplicate or stale Peras objects cause sustained validation/storage churn.
- Fast validation: Add object-diffusion tests that deliver votes/certs before and after their block context.
