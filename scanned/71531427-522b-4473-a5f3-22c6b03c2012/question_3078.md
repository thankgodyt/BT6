# Q3078: mempool acceptance compared in dualExtValidationErrorMain

## Question
Can an unprivileged attacker reach dualExtValidationErrorMain with mempool acceptance compared with block application and ledger tables, diffs, mempool transactions, snapshot selection, state-query target, and block validation timing, then cause honest nodes to select different tips in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Dual.hs / dualExtValidationErrorMain
- Entrypoint: Remote peer provides blocks/transactions that drive consensus ledger validation, replay, snapshots, or queries through normal node operation.
- Attacker controls: ledger tables, diffs, mempool transactions, snapshot selection, state-query target, and block validation timing.
- Exploit idea: Drive `dualExtValidationErrorMain` in `Ouroboros.Consensus.Ledger.Dual` through the production entrypoint using mempool acceptance compared with block application; verify whether the path can cause honest nodes to select different tips before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A query or inspection path must not expose or use stale ledger state in a way that affects validation or block production.
- Expected Cardano/Intersect impact: Potential Critical if consensus accepts a block whose ledger transition is invalid under the selected state.
- Fast validation: Create a ledger integration property comparing consensus validation, direct ledger application, and replay from snapshot.
