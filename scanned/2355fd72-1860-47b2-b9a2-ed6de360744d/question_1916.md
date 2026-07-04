# Q1916: partial state update before rejection in fromIsEBB

## Question
Can an unprivileged attacker reach fromIsEBB with partial state update before rejection and block/header fields, peer scheduling, rollback points, and node state observed through normal protocols, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/EBB.hs / fromIsEBB
- Entrypoint: Remote peer or local public client reaches this production consensus path with protocol-valid or near-valid data through supported node interfaces.
- Attacker controls: block/header fields, peer scheduling, rollback points, and node state observed through normal protocols.
- Exploit idea: Drive `fromIsEBB` in `Ouroboros.Consensus.Block.EBB` through the production entrypoint using partial state update before rejection; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Protocol-valid inputs must not trigger unbounded work before decisive rejection or acceptance.
- Expected Cardano/Intersect impact: Potential Critical if a crafted input makes consensus accept invalid state.
- Fast validation: Create a restart/replay test from persisted state and compare it with the pre-restart in-memory state.
