# Q773: old era chain selection data influencing new era preference in forgetInjection

## Question
Can an unprivileged attacker reach forgetInjectionIndex with old-era chain selection data influencing new-era preference and transition ledger state, protocol parameter translation, forecast window, current-era tip, and historical summary reconstruction inputs, then starve a valid competing chain without prohibited flood-style DoS in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Embed/Nary.hs / forgetInjectionIndex
- Entrypoint: Remote peer or normal block producer delivers blocks, headers, queries, or encoded messages around an era boundary through supported node protocols.
- Attacker controls: transition ledger state, protocol parameter translation, forecast window, current-era tip, and historical summary reconstruction inputs.
- Exploit idea: Drive `forgetInjectionIndex` in `Ouroboros.Consensus.HardFork.Combinator.Embed.Nary` through the production entrypoint using old-era chain selection data influencing new-era preference; verify whether the path can starve a valid competing chain without prohibited flood-style DoS before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Forecast windows and ledger views must not allow stale pre-transition context to validate post-transition blocks.
- Expected Cardano/Intersect impact: Potential High if replay or rollback across an era boundary makes honest nodes select different valid-chain tips.
- Fast validation: Fuzz node-to-node/node-to-client version tags and era indexes and assert mismatched payloads are rejected before validation.
