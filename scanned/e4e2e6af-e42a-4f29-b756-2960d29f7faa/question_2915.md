# Q2915: duplicate submit remove re add transaction sequences in isMempoolTxRejected

## Question
Can an unprivileged attacker reach isMempoolTxRejected with duplicate submit/remove/re-add transaction sequences and transaction sequence position, re-add timing, removal timing, post-rollback ledger state, and block-forging selection boundary, then starve a valid competing chain without prohibited flood-style DoS in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Mempool/API.hs / isMempoolTxRejected
- Entrypoint: Transaction author submits crafted transactions through LocalTxSubmission or peer propagation, then normal rollback/replay/forging paths consume the mempool state.
- Attacker controls: transaction sequence position, re-add timing, removal timing, post-rollback ledger state, and block-forging selection boundary.
- Exploit idea: Drive `isMempoolTxRejected` in `Ouroboros.Consensus.Mempool.API` through the production entrypoint using duplicate submit/remove/re-add transaction sequences; verify whether the path can starve a valid competing chain without prohibited flood-style DoS before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Rollback, replay, and era transition must revalidate or evict transactions before they can be forged into rejected blocks.
- Expected Cardano/Intersect impact: Potential Critical if the path lets a crafted transaction or block make an honest node accept an invalid ledger transition.
- Fast validation: Build a mempool-vs-block validation test using the same transaction and ledger state before and after rollback.
