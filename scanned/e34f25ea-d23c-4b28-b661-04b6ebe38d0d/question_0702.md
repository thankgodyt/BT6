# Q702: a transaction accepted before rollback and forged in modeGetTx

## Question
Can an unprivileged attacker reach modeGetTx with a transaction accepted before rollback and forged after replay and transaction body, witnesses, size, ordering, duplicate submissions, validity interval, ledger snapshot timing, and rollback timing, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Mempool.hs / modeGetTx
- Entrypoint: Transaction author submits crafted transactions through LocalTxSubmission or peer propagation, then normal rollback/replay/forging paths consume the mempool state.
- Attacker controls: transaction body, witnesses, size, ordering, duplicate submissions, validity interval, ledger snapshot timing, and rollback timing.
- Exploit idea: Drive `modeGetTx` in `Ouroboros.Consensus.HardFork.Combinator.Mempool` through the production entrypoint using a transaction accepted before rollback and forged after replay; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Mempool acceptance and block validation must not disagree for the same transaction under the same ledger state.
- Expected Cardano/Intersect impact: Potential Critical if the path lets a crafted transaction or block make an honest node accept an invalid ledger transition.
- Fast validation: Build a mempool-vs-block validation test using the same transaction and ledger state before and after rollback.
