# Q1596: boundary slots points and hashes in SanityCheckIssue

## Question
Can an unprivileged attacker reach SanityCheckIssue with boundary slots, points, and hashes and slots, points, hashes, fragments, peer timing, rollbacks, serialized data, and restart timing, then cause honest nodes to select different tips in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsSanityCheck.hs / SanityCheckIssue
- Entrypoint: Remote peer or local public client reaches this production consensus path with protocol-valid or near-valid data through supported node interfaces.
- Attacker controls: slots, points, hashes, fragments, peer timing, rollbacks, serialized data, and restart timing.
- Exploit idea: Drive `SanityCheckIssue` in `Ouroboros.Consensus.Block.SupportsSanityCheck` through the production entrypoint using boundary slots, points, and hashes; verify whether the path can cause honest nodes to select different tips before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Consensus state derived from peer data must be deterministic across honest nodes that eventually receive the same valid inputs.
- Expected Cardano/Intersect impact: Potential High if adversarial but protocol-reachable data makes honest nodes prefer different chain state.
- Fast validation: Write a property test that feeds equivalent fragments in different valid orders and compares selected tip, ledger hash, and consensus state.
