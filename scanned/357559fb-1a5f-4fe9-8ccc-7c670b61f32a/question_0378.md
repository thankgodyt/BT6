# Q378: conflicting transactions in jsonMempoolRejectionDetails

## Question
Can an unprivileged attacker reach jsonMempoolRejectionDetails with conflicting transactions with stale revalidation results and submitted transaction batches, invalid-after/revalidation timing, ledger table dependencies, and forged block ordering, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Mempool/Impl/Common.hs / jsonMempoolRejectionDetails
- Entrypoint: Transaction author submits crafted transactions through LocalTxSubmission or peer propagation, then normal rollback/replay/forging paths consume the mempool state.
- Attacker controls: submitted transaction batches, invalid-after/revalidation timing, ledger table dependencies, and forged block ordering.
- Exploit idea: Drive `jsonMempoolRejectionDetails` in `Ouroboros.Consensus.Mempool.Impl.Common` through the production entrypoint using conflicting transactions with stale revalidation results; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A block producer must not forge locally accepted transactions that other honest nodes reject under equivalent state.
- Expected Cardano/Intersect impact: Potential Critical if the path lets a crafted transaction or block make an honest node accept an invalid ledger transition.
- Fast validation: Build a mempool-vs-block validation test using the same transaction and ledger state before and after rollback.
