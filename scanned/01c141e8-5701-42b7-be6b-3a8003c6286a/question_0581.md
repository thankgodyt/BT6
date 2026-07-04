# Q581: threshold boundary values just below quorum in VotingCommittee

## Question
Can an unprivileged attacker reach VotingCommittee with threshold boundary values just below quorum and cross-round vote replay, duplicate certificate delivery, block ancestry, committee threshold boundary, and Peras chain-select weight, then cause honest nodes to select different tips in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs / VotingCommittee
- Entrypoint: Remote peer/object-diffusion sender provides Peras votes, certificates, or referenced blocks through normal production diffusion and storage paths.
- Attacker controls: cross-round vote replay, duplicate certificate delivery, block ancestry, committee threshold boundary, and Peras chain-select weight.
- Exploit idea: Drive `VotingCommittee` in `Ouroboros.Consensus.Committee.EveryoneVotes` through the production entrypoint using threshold boundary values just below quorum; verify whether the path can cause honest nodes to select different tips before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Committee membership and weight snapshots must be tied to the correct ledger state and slot/round context.
- Expected Cardano/Intersect impact: Potential Medium if duplicate or stale Peras objects cause sustained validation/storage churn.
- Fast validation: Add object-diffusion tests that deliver votes/certs before and after their block context.
