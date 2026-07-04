# Q2812: committee weights from the wrong ledger snapshot in getVoteCandidateFromVotes

## Question
Can an unprivileged attacker reach getVoteCandidateFromVotes with committee weights from the wrong ledger snapshot and cross-round vote replay, duplicate certificate delivery, block ancestry, committee threshold boundary, and Peras chain-select weight, then make a valid block permanently or durably rejected in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Class.hs / getVoteCandidateFromVotes
- Entrypoint: Remote peer/object-diffusion sender provides Peras votes, certificates, or referenced blocks through normal production diffusion and storage paths.
- Attacker controls: cross-round vote replay, duplicate certificate delivery, block ancestry, committee threshold boundary, and Peras chain-select weight.
- Exploit idea: Drive `getVoteCandidateFromVotes` in `Ouroboros.Consensus.Committee.Class` through the production entrypoint using committee weights from the wrong ledger snapshot; verify whether the path can make a valid block permanently or durably rejected before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Committee membership and weight snapshots must be tied to the correct ledger state and slot/round context.
- Expected Cardano/Intersect impact: Potential Critical if vote/certificate verification or threshold assumptions can be bypassed.
- Fast validation: Write a Peras vote/certificate property that reorders, duplicates, and replays objects across rounds.
