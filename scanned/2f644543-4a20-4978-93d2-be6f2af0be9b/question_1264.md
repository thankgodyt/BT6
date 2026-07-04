# Q1264: partial state update before rejection in mapNestedCtxt

## Question
Can an unprivileged attacker reach mapNestedCtxt with partial state update before rejection and block/header fields, peer scheduling, rollback points, and node state observed through normal protocols, then make an invalid block or ledger state appear acceptable in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/NestedContent.hs / mapNestedCtxt
- Entrypoint: Remote peer or local public client reaches this production consensus path with protocol-valid or near-valid data through supported node interfaces.
- Attacker controls: block/header fields, peer scheduling, rollback points, and node state observed through normal protocols.
- Exploit idea: Drive `mapNestedCtxt` in `Ouroboros.Consensus.Block.NestedContent` through the production entrypoint using partial state update before rejection; verify whether the path can make an invalid block or ledger state appear acceptable before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Protocol-valid inputs must not trigger unbounded work before decisive rejection or acceptance.
- Expected Cardano/Intersect impact: Potential Critical if a crafted input makes consensus accept invalid state.
- Fast validation: Create a restart/replay test from persisted state and compare it with the pre-restart in-memory state.
