# Q3578: threshold boundary values just below quorum in NormalizedVRFOutput

## Question
Can an unprivileged attacker reach NormalizedVRFOutput with threshold boundary values just below quorum and cross-round vote replay, duplicate certificate delivery, block ancestry, committee threshold boundary, and Peras chain-select weight, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto.hs / NormalizedVRFOutput
- Entrypoint: Remote peer/object-diffusion sender provides Peras votes, certificates, or referenced blocks through normal production diffusion and storage paths.
- Attacker controls: cross-round vote replay, duplicate certificate delivery, block ancestry, committee threshold boundary, and Peras chain-select weight.
- Exploit idea: Drive `NormalizedVRFOutput` in `Ouroboros.Consensus.Committee.Crypto` through the production entrypoint using threshold boundary values just below quorum; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Committee membership and weight snapshots must be tied to the correct ledger state and slot/round context.
- Expected Cardano/Intersect impact: Potential High if Peras weighting makes honest nodes prefer a non-canonical or less-secure chain.
- Fast validation: Create a committee-weight snapshot test comparing live and replayed ledger states for the same round and selected block.
