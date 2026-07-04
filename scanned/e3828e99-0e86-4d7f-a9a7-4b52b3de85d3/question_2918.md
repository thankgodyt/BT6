# Q2918: capacity accounting in getCurrentTip

## Question
Can an unprivileged attacker reach getCurrentTip with capacity accounting around maximum transaction size and transaction body, witnesses, size, ordering, duplicate submissions, validity interval, ledger snapshot timing, and rollback timing, then reuse stale validation or ledger context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Mempool/Init.hs / getCurrentTip
- Entrypoint: Transaction author submits crafted transactions through LocalTxSubmission or peer propagation, then normal rollback/replay/forging paths consume the mempool state.
- Attacker controls: transaction body, witnesses, size, ordering, duplicate submissions, validity interval, ledger snapshot timing, and rollback timing.
- Exploit idea: Drive `getCurrentTip` in `Ouroboros.Consensus.Mempool.Init` through the production entrypoint using capacity accounting around maximum transaction size; verify whether the path can reuse stale validation or ledger context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Mempool acceptance and block validation must not disagree for the same transaction under the same ledger state.
- Expected Cardano/Intersect impact: Potential Critical if the path lets a crafted transaction or block make an honest node accept an invalid ledger transition.
- Fast validation: Build a mempool-vs-block validation test using the same transaction and ledger state before and after rollback.
