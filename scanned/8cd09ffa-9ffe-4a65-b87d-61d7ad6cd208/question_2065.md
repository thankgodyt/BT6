# Q2065: ledger translation during rollback across an era boundary in ShelleyTentativeH

## Question
Can an unprivileged attacker reach ShelleyTentativeHeaderState with ledger translation during rollback across an era boundary and node-to-node encoded blocks, node-to-client query/result encodings, era indexes, hard-fork state telescope position, and rollback point, then reuse stale validation or ledger context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Node/DiffusionPipelining.hs / ShelleyTentativeHeaderState
- Entrypoint: Remote peer or normal block producer delivers blocks, headers, queries, or encoded messages around an era boundary through supported node protocols.
- Attacker controls: node-to-node encoded blocks, node-to-client query/result encodings, era indexes, hard-fork state telescope position, and rollback point.
- Exploit idea: Drive `ShelleyTentativeHeaderState` in `Ouroboros.Consensus.Shelley.Node.DiffusionPipelining` through the production entrypoint using ledger translation during rollback across an era boundary; verify whether the path can reuse stale validation or ledger context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Node-to-node and node-to-client version negotiation must not decode one era or query as another.
- Expected Cardano/Intersect impact: Potential Critical if a crafted boundary block causes honest nodes to disagree on block validity or accept invalid state.
- Fast validation: Replay the same multi-era chain live and from persisted storage and compare hard-fork summary, selected tip, and ledger state hash.
