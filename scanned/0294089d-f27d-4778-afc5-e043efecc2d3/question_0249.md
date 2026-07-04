# Q249: votes replayed across rounds or sibling blocks in getVotingCommitteeForElectio

## Question
Can an unprivileged attacker reach getVotingCommitteeForElection with votes replayed across rounds or sibling blocks and candidate vote sets, certificate bytes, round numbers, selected block references, object arrival order, and ledger-state-derived committee snapshots, then make an invalid block or ledger state appear acceptable in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/AcrossEpochs.hs / getVotingCommitteeForElection
- Entrypoint: Remote peer/object-diffusion sender provides Peras votes, certificates, or referenced blocks through normal production diffusion and storage paths.
- Attacker controls: candidate vote sets, certificate bytes, round numbers, selected block references, object arrival order, and ledger-state-derived committee snapshots.
- Exploit idea: Drive `getVotingCommitteeForElection` in `Ouroboros.Consensus.Committee.AcrossEpochs` through the production entrypoint using votes replayed across rounds or sibling blocks; verify whether the path can make an invalid block or ledger state appear acceptable before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Duplicate, stale, or cross-round votes/certificates must not be aggregated into a certificate accepted for another block or round.
- Expected Cardano/Intersect impact: Potential Critical if vote/certificate verification or threshold assumptions can be bypassed.
- Fast validation: Write a Peras vote/certificate property that reorders, duplicates, and replays objects across rounds.
