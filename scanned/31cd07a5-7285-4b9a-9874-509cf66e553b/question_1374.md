# Q1374: ledger translation during rollback across an era boundary in toByronSlotNo

## Question
Can an unprivileged attacker reach toByronSlotNo with ledger translation during rollback across an era boundary and node-to-node encoded blocks, node-to-client query/result encodings, era indexes, hard-fork state telescope position, and rollback point, then make a valid block permanently or durably rejected in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-cardano/src/byron/Ouroboros/Consensus/Byron/Ledger/Conversions.hs / toByronSlotNo
- Entrypoint: Remote peer or normal block producer delivers blocks, headers, queries, or encoded messages around an era boundary through supported node protocols.
- Attacker controls: node-to-node encoded blocks, node-to-client query/result encodings, era indexes, hard-fork state telescope position, and rollback point.
- Exploit idea: Drive `toByronSlotNo` in `Ouroboros.Consensus.Byron.Ledger.Conversions` through the production entrypoint using ledger translation during rollback across an era boundary; verify whether the path can make a valid block permanently or durably rejected before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Node-to-node and node-to-client version negotiation must not decode one era or query as another.
- Expected Cardano/Intersect impact: Potential High if an era-boundary, forecast, ledger-view, query, or network-version mismatch breaks cross-era consensus invariants for production nodes.
- Fast validation: Create a hard-fork combinator test with boundary-slot blocks and assert header era, body era, ledger view, and protocol state agree.
