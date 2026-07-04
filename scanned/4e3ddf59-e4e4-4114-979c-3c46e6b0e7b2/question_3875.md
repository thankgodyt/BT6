# Q3875: restart replay in noDefault

## Question
Can an unprivileged attacker reach noDefault with restart replay after normal synchronization and near-valid blocks or messages, chain fragment shape, state transition ordering, and replay/recovery timing, then make a valid block permanently or durably rejected in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Args.hs / noDefault
- Entrypoint: Remote peer or local public client reaches this production consensus path with protocol-valid or near-valid data through supported node interfaces.
- Attacker controls: near-valid blocks or messages, chain fragment shape, state transition ordering, and replay/recovery timing.
- Exploit idea: Drive `noDefault` in `Ouroboros.Consensus.Util.Args` through the production entrypoint using restart replay after normal synchronization; verify whether the path can make a valid block permanently or durably rejected before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Restart, rollback, and replay must not change the security meaning of an already validated chain fragment.
- Expected Cardano/Intersect impact: Potential Medium if near-valid data creates sustained resource exhaustion without prohibited flood-style DoS.
- Fast validation: Fuzz boundary slots, points, hashes, and serialized values and assert rejection happens before partial state update.
