# Q3678: duplicate submit remove re add transaction sequences in txInBlockSize

## Question
Can an unprivileged attacker reach txInBlockSize with duplicate submit/remove/re-add transaction sequences and transaction sequence position, re-add timing, removal timing, post-rollback ledger state, and block-forging selection boundary, then make an invalid block or ledger state appear acceptable in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Mempool.hs / txInBlockSize
- Entrypoint: Transaction author submits crafted transactions through LocalTxSubmission or peer propagation, then normal rollback/replay/forging paths consume the mempool state.
- Attacker controls: transaction sequence position, re-add timing, removal timing, post-rollback ledger state, and block-forging selection boundary.
- Exploit idea: Drive `txInBlockSize` in `Ouroboros.Consensus.Shelley.Ledger.Mempool` through the production entrypoint using duplicate submit/remove/re-add transaction sequences; verify whether the path can make an invalid block or ledger state appear acceptable before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Rollback, replay, and era transition must revalidate or evict transactions before they can be forged into rejected blocks.
- Expected Cardano/Intersect impact: Potential Critical if the path lets a crafted transaction or block make an honest node accept an invalid ledger transition.
- Fast validation: Build a mempool-vs-block validation test using the same transaction and ledger state before and after rollback.
