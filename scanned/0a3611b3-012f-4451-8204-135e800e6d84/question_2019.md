# Q2019: conflicting transactions in lookupByTicketNo

## Question
Can an unprivileged attacker reach lookupByTicketNo with conflicting transactions with stale revalidation results and submitted transaction batches, invalid-after/revalidation timing, ledger table dependencies, and forged block ordering, then confuse header/body, era, or storage context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Mempool/TxSeq.hs / lookupByTicketNo
- Entrypoint: Transaction author submits crafted transactions through LocalTxSubmission or peer propagation, then normal rollback/replay/forging paths consume the mempool state.
- Attacker controls: submitted transaction batches, invalid-after/revalidation timing, ledger table dependencies, and forged block ordering.
- Exploit idea: Drive `lookupByTicketNo` in `Ouroboros.Consensus.Mempool.TxSeq` through the production entrypoint using conflicting transactions with stale revalidation results; verify whether the path can confuse header/body, era, or storage context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A block producer must not forge locally accepted transactions that other honest nodes reject under equivalent state.
- Expected Cardano/Intersect impact: Potential Medium if peer-submitted transactions create sustained validation churn without prohibited flood-style DoS.
- Fast validation: Write a TxSeq/property test for duplicate submit/remove/re-add sequences and assert deterministic ordering.
