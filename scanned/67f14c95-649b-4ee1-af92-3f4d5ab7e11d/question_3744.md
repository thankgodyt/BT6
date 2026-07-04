# Q3744: hard fork telescope recovery in dispatchEncoderErr

## Question
Can an unprivileged attacker reach dispatchEncoderErr with hard-fork telescope recovery after restart and node-to-node encoded blocks, node-to-client query/result encodings, era indexes, hard-fork state telescope position, and rollback point, then reuse stale validation or ledger context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Serialisation/SerialiseNodeToClient.hs / dispatchEncoderErr
- Entrypoint: Remote peer or normal block producer delivers blocks, headers, queries, or encoded messages around an era boundary through supported node protocols.
- Attacker controls: node-to-node encoded blocks, node-to-client query/result encodings, era indexes, hard-fork state telescope position, and rollback point.
- Exploit idea: Drive `dispatchEncoderErr` in `Ouroboros.Consensus.HardFork.Combinator.Serialisation.SerialiseNodeToClient` through the production entrypoint using hard-fork telescope recovery after restart; verify whether the path can reuse stale validation or ledger context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Node-to-node and node-to-client version negotiation must not decode one era or query as another.
- Expected Cardano/Intersect impact: Potential High if an era-boundary, forecast, ledger-view, query, or network-version mismatch breaks cross-era consensus invariants for production nodes.
- Fast validation: Create a hard-fork combinator test with boundary-slot blocks and assert header era, body era, ledger view, and protocol state agree.
