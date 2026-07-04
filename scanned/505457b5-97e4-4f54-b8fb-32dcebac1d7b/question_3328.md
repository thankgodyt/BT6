# Q3328: votes replayed across rounds or sibling blocks in PoolId

## Question
Can an unprivileged attacker reach PoolId with votes replayed across rounds or sibling blocks and candidate vote sets, certificate bytes, round numbers, selected block references, object arrival order, and ledger-state-derived committee snapshots, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Types.hs / PoolId
- Entrypoint: Remote peer/object-diffusion sender provides Peras votes, certificates, or referenced blocks through normal production diffusion and storage paths.
- Attacker controls: candidate vote sets, certificate bytes, round numbers, selected block references, object arrival order, and ledger-state-derived committee snapshots.
- Exploit idea: Drive `PoolId` in `Ouroboros.Consensus.Committee.Types` through the production entrypoint using votes replayed across rounds or sibling blocks; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Duplicate, stale, or cross-round votes/certificates must not be aggregated into a certificate accepted for another block or round.
- Expected Cardano/Intersect impact: Potential High if Peras weighting makes honest nodes prefer a non-canonical or less-secure chain.
- Fast validation: Create a committee-weight snapshot test comparing live and replayed ledger states for the same round and selected block.
