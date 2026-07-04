# Q2659: a transaction accepted before rollback and forged in isMempoolTxAdded

## Question
Can an unprivileged attacker reach isMempoolTxAdded with a transaction accepted before rollback and forged after replay and transaction body, witnesses, size, ordering, duplicate submissions, validity interval, ledger snapshot timing, and rollback timing, then cause honest nodes to select different tips in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Mempool/API.hs / isMempoolTxAdded
- Entrypoint: Transaction author submits crafted transactions through LocalTxSubmission or peer propagation, then normal rollback/replay/forging paths consume the mempool state.
- Attacker controls: transaction body, witnesses, size, ordering, duplicate submissions, validity interval, ledger snapshot timing, and rollback timing.
- Exploit idea: Drive `isMempoolTxAdded` in `Ouroboros.Consensus.Mempool.API` through the production entrypoint using a transaction accepted before rollback and forged after replay; verify whether the path can cause honest nodes to select different tips before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Mempool acceptance and block validation must not disagree for the same transaction under the same ledger state.
- Expected Cardano/Intersect impact: Potential Medium if peer-submitted transactions create sustained validation churn without prohibited flood-style DoS.
- Fast validation: Write a TxSeq/property test for duplicate submit/remove/re-add sequences and assert deterministic ordering.
