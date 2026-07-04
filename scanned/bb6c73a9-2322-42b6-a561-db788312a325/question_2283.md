# Q2283: security parameter edge values in noThunksInvariant

## Question
Can an unprivileged attacker reach noThunksInvariant with security-parameter edge values and valid-looking protocol data, duplicate inputs, boundary values, stale state, and competing arrival order, then make an invalid block or ledger state appear acceptable in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/NormalForm/Invariant.hs / noThunksInvariant
- Entrypoint: Remote peer or local public client reaches this production consensus path with protocol-valid or near-valid data through supported node interfaces.
- Attacker controls: valid-looking protocol data, duplicate inputs, boundary values, stale state, and competing arrival order.
- Exploit idea: Drive `noThunksInvariant` in `Ouroboros.Consensus.Util.NormalForm.Invariant` through the production entrypoint using security-parameter edge values; verify whether the path can make an invalid block or ledger state appear acceptable before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Boundary values for slots, points, hashes, and fragments must not cause accepted state to diverge across validation paths.
- Expected Cardano/Intersect impact: Potential Critical if a crafted input makes consensus accept invalid state.
- Fast validation: Create a restart/replay test from persisted state and compare it with the pre-restart in-memory state.
