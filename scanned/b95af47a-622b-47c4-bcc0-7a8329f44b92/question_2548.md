# Q2548: duplicate votes for the same round and block in Cert

## Question
Can an unprivileged attacker reach Cert with duplicate votes for the same round and block and votes, certificates, rounds, block references, committee member identifiers, weights, duplicate object-diffusion items, and stale inclusion evidence, then reuse stale validation or ledger context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs / Cert
- Entrypoint: Remote peer/object-diffusion sender provides Peras votes, certificates, or referenced blocks through normal production diffusion and storage paths.
- Attacker controls: votes, certificates, rounds, block references, committee member identifiers, weights, duplicate object-diffusion items, and stale inclusion evidence.
- Exploit idea: Drive `Cert` in `Ouroboros.Consensus.Committee.WFALS` through the production entrypoint using duplicate votes for the same round and block; verify whether the path can reuse stale validation or ledger context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Peras votes, certificates, committee weights, and selection views must not change chain preference unless their verification assumptions hold.
- Expected Cardano/Intersect impact: Potential Critical if vote/certificate verification or threshold assumptions can be bypassed.
- Fast validation: Write a Peras vote/certificate property that reorders, duplicates, and replays objects across rounds.
