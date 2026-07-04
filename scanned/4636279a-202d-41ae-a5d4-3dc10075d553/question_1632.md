# Q1632: serialized data reused under another context in newEmptyMVar

## Question
Can an unprivileged attacker reach newEmptyMVar with serialized data reused under another context and slots, points, hashes, fragments, peer timing, rollbacks, serialized data, and restart timing, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/NormalForm/StrictMVar.hs / newEmptyMVar
- Entrypoint: Remote peer or local public client reaches this production consensus path with protocol-valid or near-valid data through supported node interfaces.
- Attacker controls: slots, points, hashes, fragments, peer timing, rollbacks, serialized data, and restart timing.
- Exploit idea: Drive `newEmptyMVar` in `Ouroboros.Consensus.Util.NormalForm.StrictMVar` through the production entrypoint using serialized data reused under another context; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Consensus state derived from peer data must be deterministic across honest nodes that eventually receive the same valid inputs.
- Expected Cardano/Intersect impact: Potential High if adversarial but protocol-reachable data makes honest nodes prefer different chain state.
- Fast validation: Write a property test that feeds equivalent fragments in different valid orders and compares selected tip, ledger hash, and consensus state.
