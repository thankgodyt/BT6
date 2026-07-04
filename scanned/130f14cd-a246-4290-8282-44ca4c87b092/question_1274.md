# Q1274: security parameter edge values in SystemClockMovedBackException

## Question
Can an unprivileged attacker reach SystemClockMovedBackException with security-parameter edge values and valid-looking protocol data, duplicate inputs, boundary values, stale state, and competing arrival order, then starve a valid competing chain without prohibited flood-style DoS in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/BlockchainTime/WallClock/Util.hs / SystemClockMovedBackException
- Entrypoint: Remote peer or local public client reaches this production consensus path with protocol-valid or near-valid data through supported node interfaces.
- Attacker controls: valid-looking protocol data, duplicate inputs, boundary values, stale state, and competing arrival order.
- Exploit idea: Drive `SystemClockMovedBackException` in `Ouroboros.Consensus.BlockchainTime.WallClock.Util` through the production entrypoint using security-parameter edge values; verify whether the path can starve a valid competing chain without prohibited flood-style DoS before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Boundary values for slots, points, hashes, and fragments must not cause accepted state to diverge across validation paths.
- Expected Cardano/Intersect impact: Potential Medium if near-valid data creates sustained resource exhaustion without prohibited flood-style DoS.
- Fast validation: Fuzz boundary slots, points, hashes, and serialized values and assert rejection happens before partial state update.
