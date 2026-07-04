# Q3428: a transaction accepted before rollback and forged in fromList

## Question
Can an unprivileged attacker reach fromList with a transaction accepted before rollback and forged after replay and transaction body, witnesses, size, ordering, duplicate submissions, validity interval, ledger snapshot timing, and rollback timing, then reuse stale validation or ledger context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Mempool/TxSeq.hs / fromList
- Entrypoint: Transaction author submits crafted transactions through LocalTxSubmission or peer propagation, then normal rollback/replay/forging paths consume the mempool state.
- Attacker controls: transaction body, witnesses, size, ordering, duplicate submissions, validity interval, ledger snapshot timing, and rollback timing.
- Exploit idea: Drive `fromList` in `Ouroboros.Consensus.Mempool.TxSeq` through the production entrypoint using a transaction accepted before rollback and forged after replay; verify whether the path can reuse stale validation or ledger context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Mempool acceptance and block validation must not disagree for the same transaction under the same ledger state.
- Expected Cardano/Intersect impact: Potential High if an honest producer can forge locally accepted transactions that other honest nodes reject under equivalent state.
- Fast validation: Create a local forging test that accepts transactions, rolls back, revalidates, and validates the forged block on a second node.
