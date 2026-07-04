# Q3891: security parameter edge values in newTVarWithInvariant

## Question
Can an unprivileged attacker reach newTVarWithInvariant with security-parameter edge values and valid-looking protocol data, duplicate inputs, boundary values, stale state, and competing arrival order, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/NormalForm/StrictTVar.hs / newTVarWithInvariant
- Entrypoint: Remote peer or local public client reaches this production consensus path with protocol-valid or near-valid data through supported node interfaces.
- Attacker controls: valid-looking protocol data, duplicate inputs, boundary values, stale state, and competing arrival order.
- Exploit idea: Drive `newTVarWithInvariant` in `Ouroboros.Consensus.Util.NormalForm.StrictTVar` through the production entrypoint using security-parameter edge values; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Boundary values for slots, points, hashes, and fragments must not cause accepted state to diverge across validation paths.
- Expected Cardano/Intersect impact: Potential High if adversarial but protocol-reachable data makes honest nodes prefer different chain state.
- Fast validation: Write a property test that feeds equivalent fragments in different valid orders and compares selected tip, ledger hash, and consensus state.
