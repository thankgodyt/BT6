# Q2216: committee weights from the wrong ledger snapshot in HasBLSContext

## Question
Can an unprivileged attacker reach HasBLSContext with committee weights from the wrong ledger snapshot and cross-round vote replay, duplicate certificate delivery, block ancestry, committee threshold boundary, and Peras chain-select weight, then reuse stale validation or ledger context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs / HasBLSContext
- Entrypoint: Remote peer/object-diffusion sender provides Peras votes, certificates, or referenced blocks through normal production diffusion and storage paths.
- Attacker controls: cross-round vote replay, duplicate certificate delivery, block ancestry, committee threshold boundary, and Peras chain-select weight.
- Exploit idea: Drive `HasBLSContext` in `Ouroboros.Consensus.Committee.Crypto.BLS` through the production entrypoint using committee weights from the wrong ledger snapshot; verify whether the path can reuse stale validation or ledger context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Committee membership and weight snapshots must be tied to the correct ledger state and slot/round context.
- Expected Cardano/Intersect impact: Potential Critical if vote/certificate verification or threshold assumptions can be bypassed.
- Fast validation: Write a Peras vote/certificate property that reorders, duplicates, and replays objects across rounds.
