# Q1390: ledger translation during rollback across an era boundary in Ouroboros Consens

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.Cardano.Node with ledger translation during rollback across an era boundary and node-to-node encoded blocks, node-to-client query/result encodings, era indexes, hard-fork state telescope position, and rollback point, then make a valid block permanently or durably rejected in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-cardano/src/ouroboros-consensus-cardano/Ouroboros/Consensus/Cardano/Node.hs / Ouroboros.Consensus.Cardano.Node
- Entrypoint: Remote peer or normal block producer delivers blocks, headers, queries, or encoded messages around an era boundary through supported node protocols.
- Attacker controls: node-to-node encoded blocks, node-to-client query/result encodings, era indexes, hard-fork state telescope position, and rollback point.
- Exploit idea: Drive `Ouroboros.Consensus.Cardano.Node` in `Ouroboros.Consensus.Cardano.Node` through the production entrypoint using ledger translation during rollback across an era boundary; verify whether the path can make a valid block permanently or durably rejected before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Node-to-node and node-to-client version negotiation must not decode one era or query as another.
- Expected Cardano/Intersect impact: Potential Critical if a crafted boundary block causes honest nodes to disagree on block validity or accept invalid state.
- Fast validation: Replay the same multi-era chain live and from persisted storage and compare hard-fork summary, selected tip, and ledger state hash.
