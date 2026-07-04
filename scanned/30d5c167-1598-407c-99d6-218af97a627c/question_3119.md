# Q3119: same fragments delivered in different valid orders in Ouroboros Consensus Util

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.Util.FileLock with same fragments delivered in different valid orders and valid-looking protocol data, duplicate inputs, boundary values, stale state, and competing arrival order, then starve a valid competing chain without prohibited flood-style DoS in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/FileLock.hs / Ouroboros.Consensus.Util.FileLock
- Entrypoint: Remote peer or local public client reaches this production consensus path with protocol-valid or near-valid data through supported node interfaces.
- Attacker controls: valid-looking protocol data, duplicate inputs, boundary values, stale state, and competing arrival order.
- Exploit idea: Drive `Ouroboros.Consensus.Util.FileLock` in `Ouroboros.Consensus.Util.FileLock` through the production entrypoint using same fragments delivered in different valid orders; verify whether the path can starve a valid competing chain without prohibited flood-style DoS before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Boundary values for slots, points, hashes, and fragments must not cause accepted state to diverge across validation paths.
- Expected Cardano/Intersect impact: Potential High if adversarial but protocol-reachable data makes honest nodes prefer different chain state.
- Fast validation: Write a property test that feeds equivalent fragments in different valid orders and compares selected tip, ledger hash, and consensus state.
