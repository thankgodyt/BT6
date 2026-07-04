# Q1946: same fragments delivered in different valid orders in condenseListWithPadding

## Question
Can an unprivileged attacker reach condenseListWithPadding with same fragments delivered in different valid orders and valid-looking protocol data, duplicate inputs, boundary values, stale state, and competing arrival order, then starve a valid competing chain without prohibited flood-style DoS in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Condense.hs / condenseListWithPadding
- Entrypoint: Remote peer or local public client reaches this production consensus path with protocol-valid or near-valid data through supported node interfaces.
- Attacker controls: valid-looking protocol data, duplicate inputs, boundary values, stale state, and competing arrival order.
- Exploit idea: Drive `condenseListWithPadding` in `Ouroboros.Consensus.Util.Condense` through the production entrypoint using same fragments delivered in different valid orders; verify whether the path can starve a valid competing chain without prohibited flood-style DoS before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Boundary values for slots, points, hashes, and fragments must not cause accepted state to diverge across validation paths.
- Expected Cardano/Intersect impact: Potential Critical if a crafted input makes consensus accept invalid state.
- Fast validation: Create a restart/replay test from persisted state and compare it with the pre-restart in-memory state.
