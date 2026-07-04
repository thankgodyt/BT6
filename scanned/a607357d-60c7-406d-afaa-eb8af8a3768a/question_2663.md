# Q2663: same tip ledger table changes that skip revalidation in splitAfterTxSize

## Question
Can an unprivileged attacker reach splitAfterTxSize with same-tip ledger-table changes that skip revalidation and transaction sequence position, re-add timing, removal timing, post-rollback ledger state, and block-forging selection boundary, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Mempool/TxSeq.hs / splitAfterTxSize
- Entrypoint: Transaction author submits crafted transactions through LocalTxSubmission or peer propagation, then normal rollback/replay/forging paths consume the mempool state.
- Attacker controls: transaction sequence position, re-add timing, removal timing, post-rollback ledger state, and block-forging selection boundary.
- Exploit idea: Drive `splitAfterTxSize` in `Ouroboros.Consensus.Mempool.TxSeq` through the production entrypoint using same-tip ledger-table changes that skip revalidation; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Rollback, replay, and era transition must revalidate or evict transactions before they can be forged into rejected blocks.
- Expected Cardano/Intersect impact: Potential High if an honest producer can forge locally accepted transactions that other honest nodes reject under equivalent state.
- Fast validation: Create a local forging test that accepts transactions, rolls back, revalidates, and validates the forged block on a second node.
