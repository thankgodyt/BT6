# Q2574: restart replay in Ouroboros Consensus Block SupportsProtocol

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.Block.SupportsProtocol with restart replay after normal synchronization and near-valid blocks or messages, chain fragment shape, state transition ordering, and replay/recovery timing, then cause honest nodes to select different tips in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsProtocol.hs / Ouroboros.Consensus.Block.SupportsProtocol
- Entrypoint: Remote peer or local public client reaches this production consensus path with protocol-valid or near-valid data through supported node interfaces.
- Attacker controls: near-valid blocks or messages, chain fragment shape, state transition ordering, and replay/recovery timing.
- Exploit idea: Drive `Ouroboros.Consensus.Block.SupportsProtocol` in `Ouroboros.Consensus.Block.SupportsProtocol` through the production entrypoint using restart replay after normal synchronization; verify whether the path can cause honest nodes to select different tips before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Restart, rollback, and replay must not change the security meaning of an already validated chain fragment.
- Expected Cardano/Intersect impact: Potential Medium if near-valid data creates sustained resource exhaustion without prohibited flood-style DoS.
- Fast validation: Fuzz boundary slots, points, hashes, and serialized values and assert rejection happens before partial state update.
