# Q3075: committee weights from the wrong ledger snapshot in implCheckShouldVote

## Question
Can an unprivileged attacker reach implCheckShouldVote with committee weights from the wrong ledger snapshot and cross-round vote replay, duplicate certificate delivery, block ancestry, committee threshold boundary, and Peras chain-select weight, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs / implCheckShouldVote
- Entrypoint: Remote peer/object-diffusion sender provides Peras votes, certificates, or referenced blocks through normal production diffusion and storage paths.
- Attacker controls: cross-round vote replay, duplicate certificate delivery, block ancestry, committee threshold boundary, and Peras chain-select weight.
- Exploit idea: Drive `implCheckShouldVote` in `Ouroboros.Consensus.Committee.WFALS` through the production entrypoint using committee weights from the wrong ledger snapshot; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Committee membership and weight snapshots must be tied to the correct ledger state and slot/round context.
- Expected Cardano/Intersect impact: Potential Medium if duplicate or stale Peras objects cause sustained validation/storage churn.
- Fast validation: Add object-diffusion tests that deliver votes/certs before and after their block context.
