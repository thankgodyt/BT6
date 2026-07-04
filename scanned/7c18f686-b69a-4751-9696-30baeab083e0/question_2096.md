# Q2096: pre transition fragments delivered in Ouroboros Consensus HardFork Combinator 

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.HardFork.Combinator.Node.Metrics with pre-transition fragments delivered after post-transition blocks and pre-transition fragments, post-transition blocks, translation boundary, stale era context, query dispatch tags, and replay order, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Node/Metrics.hs / Ouroboros.Consensus.HardFork.Combinator.Node.Metrics
- Entrypoint: Remote peer or normal block producer delivers blocks, headers, queries, or encoded messages around an era boundary through supported node protocols.
- Attacker controls: pre-transition fragments, post-transition blocks, translation boundary, stale era context, query dispatch tags, and replay order.
- Exploit idea: Drive `Ouroboros.Consensus.HardFork.Combinator.Node.Metrics` in `Ouroboros.Consensus.HardFork.Combinator.Node.Metrics` through the production entrypoint using pre-transition fragments delivered after post-transition blocks; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Ledger translation across eras must preserve the consensus state required for chain selection and block validation.
- Expected Cardano/Intersect impact: Potential High if replay or rollback across an era boundary makes honest nodes select different valid-chain tips.
- Fast validation: Fuzz node-to-node/node-to-client version tags and era indexes and assert mismatched payloads are rejected before validation.
