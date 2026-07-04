# Q46: same tip ledger table changes that skip revalidation in mkShelleyValidatedTx

## Question
Can an unprivileged attacker reach mkShelleyValidatedTx with same-tip ledger-table changes that skip revalidation and transaction sequence position, re-add timing, removal timing, post-rollback ledger state, and block-forging selection boundary, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Mempool.hs / mkShelleyValidatedTx
- Entrypoint: Transaction author submits crafted transactions through LocalTxSubmission or peer propagation, then normal rollback/replay/forging paths consume the mempool state.
- Attacker controls: transaction sequence position, re-add timing, removal timing, post-rollback ledger state, and block-forging selection boundary.
- Exploit idea: Drive `mkShelleyValidatedTx` in `Ouroboros.Consensus.Shelley.Ledger.Mempool` through the production entrypoint using same-tip ledger-table changes that skip revalidation; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Rollback, replay, and era transition must revalidate or evict transactions before they can be forged into rejected blocks.
- Expected Cardano/Intersect impact: Potential Critical if the path lets a crafted transaction or block make an honest node accept an invalid ledger transition.
- Fast validation: Build a mempool-vs-block validation test using the same transaction and ledger state before and after rollback.
