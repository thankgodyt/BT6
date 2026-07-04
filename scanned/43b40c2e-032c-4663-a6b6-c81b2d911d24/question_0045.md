# Q45: capacity accounting in Ouroboros Consensus Byron Ledger Mempool

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.Byron.Ledger.Mempool with capacity accounting around maximum transaction size and transaction body, witnesses, size, ordering, duplicate submissions, validity interval, ledger snapshot timing, and rollback timing, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-cardano/src/byron/Ouroboros/Consensus/Byron/Ledger/Mempool.hs / Ouroboros.Consensus.Byron.Ledger.Mempool
- Entrypoint: Transaction author submits crafted transactions through LocalTxSubmission or peer propagation, then normal rollback/replay/forging paths consume the mempool state.
- Attacker controls: transaction body, witnesses, size, ordering, duplicate submissions, validity interval, ledger snapshot timing, and rollback timing.
- Exploit idea: Drive `Ouroboros.Consensus.Byron.Ledger.Mempool` in `Ouroboros.Consensus.Byron.Ledger.Mempool` through the production entrypoint using capacity accounting around maximum transaction size; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Mempool acceptance and block validation must not disagree for the same transaction under the same ledger state.
- Expected Cardano/Intersect impact: Potential Medium if peer-submitted transactions create sustained validation churn without prohibited flood-style DoS.
- Fast validation: Write a TxSeq/property test for duplicate submit/remove/re-add sequences and assert deterministic ordering.
