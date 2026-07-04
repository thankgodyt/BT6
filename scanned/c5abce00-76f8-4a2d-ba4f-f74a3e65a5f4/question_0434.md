# Q434: node to node data decoded in Ouroboros Consensus HardFork Combinator

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.HardFork.Combinator with node-to-node data decoded with a mismatched era tag and transition ledger state, protocol parameter translation, forecast window, current-era tip, and historical summary reconstruction inputs, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator.hs / Ouroboros.Consensus.HardFork.Combinator
- Entrypoint: Remote peer or normal block producer delivers blocks, headers, queries, or encoded messages around an era boundary through supported node protocols.
- Attacker controls: transition ledger state, protocol parameter translation, forecast window, current-era tip, and historical summary reconstruction inputs.
- Exploit idea: Drive `Ouroboros.Consensus.HardFork.Combinator` in `Ouroboros.Consensus.HardFork.Combinator` through the production entrypoint using node-to-node data decoded with a mismatched era tag; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Forecast windows and ledger views must not allow stale pre-transition context to validate post-transition blocks.
- Expected Cardano/Intersect impact: Potential High if replay or rollback across an era boundary makes honest nodes select different valid-chain tips.
- Fast validation: Fuzz node-to-node/node-to-client version tags and era indexes and assert mismatched payloads are rejected before validation.
