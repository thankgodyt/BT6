# Q3382: partial state update before rejection in newTVar

## Question
Can an unprivileged attacker reach newTVar with partial state update before rejection and block/header fields, peer scheduling, rollback points, and node state observed through normal protocols, then confuse header/body, era, or storage context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/NormalForm/StrictTVar.hs / newTVar
- Entrypoint: Remote peer or local public client reaches this production consensus path with protocol-valid or near-valid data through supported node interfaces.
- Attacker controls: block/header fields, peer scheduling, rollback points, and node state observed through normal protocols.
- Exploit idea: Drive `newTVar` in `Ouroboros.Consensus.Util.NormalForm.StrictTVar` through the production entrypoint using partial state update before rejection; verify whether the path can confuse header/body, era, or storage context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Protocol-valid inputs must not trigger unbounded work before decisive rejection or acceptance.
- Expected Cardano/Intersect impact: Potential Critical if a crafted input makes consensus accept invalid state.
- Fast validation: Create a restart/replay test from persisted state and compare it with the pre-restart in-memory state.
