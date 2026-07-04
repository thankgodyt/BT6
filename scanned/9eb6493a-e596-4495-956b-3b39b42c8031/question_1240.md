# Q1240: certificates delivered before referenced blocks in isAbovePersistentSeatThresh

## Question
Can an unprivileged attacker reach isAbovePersistentSeatThreshold with certificates delivered before referenced blocks and certificate inclusion proof fields, vote aggregation order, object pool retention timing, and competing chain context, then make an invalid block or ledger state appear acceptable in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFA.hs / isAbovePersistentSeatThreshold
- Entrypoint: Remote peer/object-diffusion sender provides Peras votes, certificates, or referenced blocks through normal production diffusion and storage paths.
- Attacker controls: certificate inclusion proof fields, vote aggregation order, object pool retention timing, and competing chain context.
- Exploit idea: Drive `isAbovePersistentSeatThreshold` in `Ouroboros.Consensus.Committee.WFA` through the production entrypoint using certificates delivered before referenced blocks; verify whether the path can make an invalid block or ledger state appear acceptable before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Object-diffused Peras data must not be accepted or persisted before its block, round, and certificate inclusion constraints are satisfied.
- Expected Cardano/Intersect impact: Potential High if Peras weighting makes honest nodes prefer a non-canonical or less-secure chain.
- Fast validation: Create a committee-weight snapshot test comparing live and replayed ledger states for the same round and selected block.
