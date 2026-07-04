# Q2540: duplicate votes for the same round and block in InterEpochVotingCommittee

## Question
Can an unprivileged attacker reach InterEpochVotingCommittee with duplicate votes for the same round and block and votes, certificates, rounds, block references, committee member identifiers, weights, duplicate object-diffusion items, and stale inclusion evidence, then reuse stale validation or ledger context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/AcrossEpochs.hs / InterEpochVotingCommittee
- Entrypoint: Remote peer/object-diffusion sender provides Peras votes, certificates, or referenced blocks through normal production diffusion and storage paths.
- Attacker controls: votes, certificates, rounds, block references, committee member identifiers, weights, duplicate object-diffusion items, and stale inclusion evidence.
- Exploit idea: Drive `InterEpochVotingCommittee` in `Ouroboros.Consensus.Committee.AcrossEpochs` through the production entrypoint using duplicate votes for the same round and block; verify whether the path can reuse stale validation or ledger context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Peras votes, certificates, committee weights, and selection views must not change chain preference unless their verification assumptions hold.
- Expected Cardano/Intersect impact: Potential High if Peras weighting makes honest nodes prefer a non-canonical or less-secure chain.
- Fast validation: Create a committee-weight snapshot test comparing live and replayed ledger states for the same round and selected block.
