# Q2075: forecast windows at their maximum allowed range in eraIndexToInt

## Question
Can an unprivileged attacker reach eraIndexToInt with forecast windows at their maximum allowed range and era-boundary slot, block/header era tags, network version, serialized query tags, ledger-view forecast timing, and predecessor chain context, then cause honest nodes to select different tips in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Abstract/SingleEraBlock.hs / eraIndexToInt
- Entrypoint: Remote peer or normal block producer delivers blocks, headers, queries, or encoded messages around an era boundary through supported node protocols.
- Attacker controls: era-boundary slot, block/header era tags, network version, serialized query tags, ledger-view forecast timing, and predecessor chain context.
- Exploit idea: Drive `eraIndexToInt` in `Ouroboros.Consensus.HardFork.Combinator.Abstract.SingleEraBlock` through the production entrypoint using forecast windows at their maximum allowed range; verify whether the path can cause honest nodes to select different tips before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A block at an era boundary must be interpreted under exactly one era for header, body, ledger, forecast, and protocol validation.
- Expected Cardano/Intersect impact: Potential High if replay or rollback across an era boundary makes honest nodes select different valid-chain tips.
- Fast validation: Fuzz node-to-node/node-to-client version tags and era indexes and assert mismatched payloads are rejected before validation.
