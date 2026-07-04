# Q1236: Peras weight conflicting in ProofOfPossession

## Question
Can an unprivileged attacker reach ProofOfPossession with Peras weight conflicting with Praos chain order and certificate inclusion proof fields, vote aggregation order, object pool retention timing, and competing chain context, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs / ProofOfPossession
- Entrypoint: Remote peer/object-diffusion sender provides Peras votes, certificates, or referenced blocks through normal production diffusion and storage paths.
- Attacker controls: certificate inclusion proof fields, vote aggregation order, object pool retention timing, and competing chain context.
- Exploit idea: Drive `ProofOfPossession` in `Ouroboros.Consensus.Committee.Crypto.BLS` through the production entrypoint using Peras weight conflicting with Praos chain order; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Object-diffused Peras data must not be accepted or persisted before its block, round, and certificate inclusion constraints are satisfied.
- Expected Cardano/Intersect impact: Potential Critical if vote/certificate verification or threshold assumptions can be bypassed.
- Fast validation: Write a Peras vote/certificate property that reorders, duplicates, and replays objects across rounds.
