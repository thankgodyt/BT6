# Q1638: restart replay in nominalDelay

## Question
Can an unprivileged attacker reach nominalDelay with restart replay after normal synchronization and near-valid blocks or messages, chain fragment shape, state transition ordering, and replay/recovery timing, then make a valid block permanently or durably rejected in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Time.hs / nominalDelay
- Entrypoint: Remote peer or local public client reaches this production consensus path with protocol-valid or near-valid data through supported node interfaces.
- Attacker controls: near-valid blocks or messages, chain fragment shape, state transition ordering, and replay/recovery timing.
- Exploit idea: Drive `nominalDelay` in `Ouroboros.Consensus.Util.Time` through the production entrypoint using restart replay after normal synchronization; verify whether the path can make a valid block permanently or durably rejected before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Restart, rollback, and replay must not change the security meaning of an already validated chain fragment.
- Expected Cardano/Intersect impact: Potential High if adversarial but protocol-reachable data makes honest nodes prefer different chain state.
- Fast validation: Write a property test that feeds equivalent fragments in different valid orders and compares selected tip, ledger hash, and consensus state.
