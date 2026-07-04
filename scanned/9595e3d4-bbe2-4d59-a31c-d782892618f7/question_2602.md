# Q2602: stale cross module state in Ouroboros Consensus Util Enclose

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.Util.Enclose with stale cross-module state after rollback and near-valid blocks or messages, chain fragment shape, state transition ordering, and replay/recovery timing, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Enclose.hs / Ouroboros.Consensus.Util.Enclose
- Entrypoint: Remote peer or local public client reaches this production consensus path with protocol-valid or near-valid data through supported node interfaces.
- Attacker controls: near-valid blocks or messages, chain fragment shape, state transition ordering, and replay/recovery timing.
- Exploit idea: Drive `Ouroboros.Consensus.Util.Enclose` in `Ouroboros.Consensus.Util.Enclose` through the production entrypoint using stale cross-module state after rollback; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Restart, rollback, and replay must not change the security meaning of an already validated chain fragment.
- Expected Cardano/Intersect impact: Potential High if adversarial but protocol-reachable data makes honest nodes prefer different chain state.
- Fast validation: Write a property test that feeds equivalent fragments in different valid orders and compares selected tip, ledger hash, and consensus state.
