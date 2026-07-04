# Q2813: certificates delivered before referenced blocks in signVote

## Question
Can an unprivileged attacker reach signVote with certificates delivered before referenced blocks and certificate inclusion proof fields, vote aggregation order, object pool retention timing, and competing chain context, then starve a valid competing chain without prohibited flood-style DoS in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto.hs / signVote
- Entrypoint: Remote peer/object-diffusion sender provides Peras votes, certificates, or referenced blocks through normal production diffusion and storage paths.
- Attacker controls: certificate inclusion proof fields, vote aggregation order, object pool retention timing, and competing chain context.
- Exploit idea: Drive `signVote` in `Ouroboros.Consensus.Committee.Crypto` through the production entrypoint using certificates delivered before referenced blocks; verify whether the path can starve a valid competing chain without prohibited flood-style DoS before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Object-diffused Peras data must not be accepted or persisted before its block, round, and certificate inclusion constraints are satisfied.
- Expected Cardano/Intersect impact: Potential High if Peras weighting makes honest nodes prefer a non-canonical or less-secure chain.
- Fast validation: Create a committee-weight snapshot test comparing live and replayed ledger states for the same round and selected block.
