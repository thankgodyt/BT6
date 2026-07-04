# Q3621: partial state update before rejection in Ouroboros Consensus Util Bitmap

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.Util.Bitmap with partial state update before rejection and block/header fields, peer scheduling, rollback points, and node state observed through normal protocols, then make an invalid block or ledger state appear acceptable in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Bitmap.hs / Ouroboros.Consensus.Util.Bitmap
- Entrypoint: Remote peer or local public client reaches this production consensus path with protocol-valid or near-valid data through supported node interfaces.
- Attacker controls: block/header fields, peer scheduling, rollback points, and node state observed through normal protocols.
- Exploit idea: Drive `Ouroboros.Consensus.Util.Bitmap` in `Ouroboros.Consensus.Util.Bitmap` through the production entrypoint using partial state update before rejection; verify whether the path can make an invalid block or ledger state appear acceptable before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Protocol-valid inputs must not trigger unbounded work before decisive rejection or acceptance.
- Expected Cardano/Intersect impact: Potential High if adversarial but protocol-reachable data makes honest nodes prefer different chain state.
- Fast validation: Write a property test that feeds equivalent fragments in different valid orders and compares selected tip, ledger hash, and consensus state.
