# Q758: the first block in getOne

## Question
Can an unprivileged attacker reach getOne with the first block after an era transition and era-boundary slot, block/header era tags, network version, serialized query tags, ledger-view forecast timing, and predecessor chain context, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/ShelleyHFC.hs / getOne
- Entrypoint: Remote peer or normal block producer delivers blocks, headers, queries, or encoded messages around an era boundary through supported node protocols.
- Attacker controls: era-boundary slot, block/header era tags, network version, serialized query tags, ledger-view forecast timing, and predecessor chain context.
- Exploit idea: Drive `getOne` in `Ouroboros.Consensus.Shelley.ShelleyHFC` through the production entrypoint using the first block after an era transition; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A block at an era boundary must be interpreted under exactly one era for header, body, ledger, forecast, and protocol validation.
- Expected Cardano/Intersect impact: Potential High if replay or rollback across an era boundary makes honest nodes select different valid-chain tips.
- Fast validation: Fuzz node-to-node/node-to-client version tags and era indexes and assert mismatched payloads are rejected before validation.
