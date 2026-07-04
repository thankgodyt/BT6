# Q1748: ledger translation during rollback across an era boundary in Ouroboros Consens

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.HardFork.Combinator.Abstract.NoHardForks with ledger translation during rollback across an era boundary and node-to-node encoded blocks, node-to-client query/result encodings, era indexes, hard-fork state telescope position, and rollback point, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Abstract/NoHardForks.hs / Ouroboros.Consensus.HardFork.Combinator.Abstract.NoHardForks
- Entrypoint: Remote peer or normal block producer delivers blocks, headers, queries, or encoded messages around an era boundary through supported node protocols.
- Attacker controls: node-to-node encoded blocks, node-to-client query/result encodings, era indexes, hard-fork state telescope position, and rollback point.
- Exploit idea: Drive `Ouroboros.Consensus.HardFork.Combinator.Abstract.NoHardForks` in `Ouroboros.Consensus.HardFork.Combinator.Abstract.NoHardForks` through the production entrypoint using ledger translation during rollback across an era boundary; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Node-to-node and node-to-client version negotiation must not decode one era or query as another.
- Expected Cardano/Intersect impact: Potential High if an era-boundary, forecast, ledger-view, query, or network-version mismatch breaks cross-era consensus invariants for production nodes.
- Fast validation: Create a hard-fork combinator test with boundary-slot blocks and assert header era, body era, ledger view, and protocol state agree.
