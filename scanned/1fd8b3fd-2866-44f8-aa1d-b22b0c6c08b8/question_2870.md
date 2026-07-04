# Q2870: boundary slots points and hashes in uncheckedNewEmptyMVar

## Question
Can an unprivileged attacker reach uncheckedNewEmptyMVar with boundary slots, points, and hashes and slots, points, hashes, fragments, peer timing, rollbacks, serialized data, and restart timing, then cause honest nodes to select different tips in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/NormalForm/StrictMVar.hs / uncheckedNewEmptyMVar
- Entrypoint: Remote peer or local public client reaches this production consensus path with protocol-valid or near-valid data through supported node interfaces.
- Attacker controls: slots, points, hashes, fragments, peer timing, rollbacks, serialized data, and restart timing.
- Exploit idea: Drive `uncheckedNewEmptyMVar` in `Ouroboros.Consensus.Util.NormalForm.StrictMVar` through the production entrypoint using boundary slots, points, and hashes; verify whether the path can cause honest nodes to select different tips before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Consensus state derived from peer data must be deterministic across honest nodes that eventually receive the same valid inputs.
- Expected Cardano/Intersect impact: Potential Critical if a crafted input makes consensus accept invalid state.
- Fast validation: Create a restart/replay test from persisted state and compare it with the pre-restart in-memory state.
