# Q707: same tip ledger table changes that skip revalidation in getCurrentTip

## Question
Can an unprivileged attacker reach getCurrentTip with same-tip ledger-table changes that skip revalidation and transaction sequence position, re-add timing, removal timing, post-rollback ledger state, and block-forging selection boundary, then make an invalid block or ledger state appear acceptable in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Mempool/Init.hs / getCurrentTip
- Entrypoint: Transaction author submits crafted transactions through LocalTxSubmission or peer propagation, then normal rollback/replay/forging paths consume the mempool state.
- Attacker controls: transaction sequence position, re-add timing, removal timing, post-rollback ledger state, and block-forging selection boundary.
- Exploit idea: Drive `getCurrentTip` in `Ouroboros.Consensus.Mempool.Init` through the production entrypoint using same-tip ledger-table changes that skip revalidation; verify whether the path can make an invalid block or ledger state appear acceptable before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Rollback, replay, and era transition must revalidate or evict transactions before they can be forged into rejected blocks.
- Expected Cardano/Intersect impact: Potential Medium if peer-submitted transactions create sustained validation churn without prohibited flood-style DoS.
- Fast validation: Write a TxSeq/property test for duplicate submit/remove/re-add sequences and assert deterministic ordering.
