# Q916: mempool acceptance compared in maxHeaderSize

## Question
Can an unprivileged attacker reach maxHeaderSize with mempool acceptance compared with block application and ledger tables, diffs, mempool transactions, snapshot selection, state-query target, and block validation timing, then make a valid block permanently or durably rejected in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/CommonProtocolParams.hs / maxHeaderSize
- Entrypoint: Remote peer provides blocks/transactions that drive consensus ledger validation, replay, snapshots, or queries through normal node operation.
- Attacker controls: ledger tables, diffs, mempool transactions, snapshot selection, state-query target, and block validation timing.
- Exploit idea: Drive `maxHeaderSize` in `Ouroboros.Consensus.Ledger.CommonProtocolParams` through the production entrypoint using mempool acceptance compared with block application; verify whether the path can make a valid block permanently or durably rejected before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A query or inspection path must not expose or use stale ledger state in a way that affects validation or block production.
- Expected Cardano/Intersect impact: Potential High if ledger view or table mismatch makes honest nodes validate the same chain differently.
- Fast validation: Build a rollback/replay test over ledger tables and assert table hashes match fresh sequential validation.
