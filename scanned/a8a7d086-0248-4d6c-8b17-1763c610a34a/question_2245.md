# Q2245: near valid protocol data reaching expensive paths in headerRealPoint

## Question
Can an unprivileged attacker reach headerRealPoint with near-valid protocol data reaching expensive paths and block/header fields, peer scheduling, rollback points, and node state observed through normal protocols, then starve a valid competing chain without prohibited flood-style DoS in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/RealPoint.hs / headerRealPoint
- Entrypoint: Remote peer or local public client reaches this production consensus path with protocol-valid or near-valid data through supported node interfaces.
- Attacker controls: block/header fields, peer scheduling, rollback points, and node state observed through normal protocols.
- Exploit idea: Drive `headerRealPoint` in `Ouroboros.Consensus.Block.RealPoint` through the production entrypoint using near-valid protocol data reaching expensive paths; verify whether the path can starve a valid competing chain without prohibited flood-style DoS before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Protocol-valid inputs must not trigger unbounded work before decisive rejection or acceptance.
- Expected Cardano/Intersect impact: Potential Medium if near-valid data creates sustained resource exhaustion without prohibited flood-style DoS.
- Fast validation: Fuzz boundary slots, points, hashes, and serialized values and assert rejection happens before partial state update.
