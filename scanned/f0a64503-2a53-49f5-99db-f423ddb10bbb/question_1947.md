# Q1947: restart replay in SameDepIndex2

## Question
Can an unprivileged attacker reach SameDepIndex2 with restart replay after normal synchronization and near-valid blocks or messages, chain fragment shape, state transition ordering, and replay/recovery timing, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/DepPair.hs / SameDepIndex2
- Entrypoint: Remote peer or local public client reaches this production consensus path with protocol-valid or near-valid data through supported node interfaces.
- Attacker controls: near-valid blocks or messages, chain fragment shape, state transition ordering, and replay/recovery timing.
- Exploit idea: Drive `SameDepIndex2` in `Ouroboros.Consensus.Util.DepPair` through the production entrypoint using restart replay after normal synchronization; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Restart, rollback, and replay must not change the security meaning of an already validated chain fragment.
- Expected Cardano/Intersect impact: Potential Medium if near-valid data creates sustained resource exhaustion without prohibited flood-style DoS.
- Fast validation: Fuzz boundary slots, points, hashes, and serialized values and assert rejection happens before partial state update.
