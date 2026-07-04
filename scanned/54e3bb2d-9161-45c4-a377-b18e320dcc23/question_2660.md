# Q2660: duplicate submit remove re add transaction sequences in computeMempoolCapacity

## Question
Can an unprivileged attacker reach computeMempoolCapacity with duplicate submit/remove/re-add transaction sequences and transaction sequence position, re-add timing, removal timing, post-rollback ledger state, and block-forging selection boundary, then make an invalid block or ledger state appear acceptable in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Mempool/Capacity.hs / computeMempoolCapacity
- Entrypoint: Transaction author submits crafted transactions through LocalTxSubmission or peer propagation, then normal rollback/replay/forging paths consume the mempool state.
- Attacker controls: transaction sequence position, re-add timing, removal timing, post-rollback ledger state, and block-forging selection boundary.
- Exploit idea: Drive `computeMempoolCapacity` in `Ouroboros.Consensus.Mempool.Capacity` through the production entrypoint using duplicate submit/remove/re-add transaction sequences; verify whether the path can make an invalid block or ledger state appear acceptable before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Rollback, replay, and era transition must revalidate or evict transactions before they can be forged into rejected blocks.
- Expected Cardano/Intersect impact: Potential Critical if the path lets a crafted transaction or block make an honest node accept an invalid ledger transition.
- Fast validation: Build a mempool-vs-block validation test using the same transaction and ledger state before and after rollback.
