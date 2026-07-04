# Q924: mempool acceptance compared in Ouroboros Consensus Ledger SupportsProtocol

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.Ledger.SupportsProtocol with mempool acceptance compared with block application and ledger tables, diffs, mempool transactions, snapshot selection, state-query target, and block validation timing, then make a valid block permanently or durably rejected in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/SupportsProtocol.hs / Ouroboros.Consensus.Ledger.SupportsProtocol
- Entrypoint: Remote peer provides blocks/transactions that drive consensus ledger validation, replay, snapshots, or queries through normal node operation.
- Attacker controls: ledger tables, diffs, mempool transactions, snapshot selection, state-query target, and block validation timing.
- Exploit idea: Drive `Ouroboros.Consensus.Ledger.SupportsProtocol` in `Ouroboros.Consensus.Ledger.SupportsProtocol` through the production entrypoint using mempool acceptance compared with block application; verify whether the path can make a valid block permanently or durably rejected before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A query or inspection path must not expose or use stale ledger state in a way that affects validation or block production.
- Expected Cardano/Intersect impact: Potential Critical if consensus accepts a block whose ledger transition is invalid under the selected state.
- Fast validation: Create a ledger integration property comparing consensus validation, direct ledger application, and replay from snapshot.
