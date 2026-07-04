# Q1116: old era chain selection data influencing new era preference in Ouroboros Conse

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.HardFork.Combinator.Node.SanityCheck with old-era chain selection data influencing new-era preference and transition ledger state, protocol parameter translation, forecast window, current-era tip, and historical summary reconstruction inputs, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Node/SanityCheck.hs / Ouroboros.Consensus.HardFork.Combinator.Node.SanityCheck
- Entrypoint: Remote peer or normal block producer delivers blocks, headers, queries, or encoded messages around an era boundary through supported node protocols.
- Attacker controls: transition ledger state, protocol parameter translation, forecast window, current-era tip, and historical summary reconstruction inputs.
- Exploit idea: Drive `Ouroboros.Consensus.HardFork.Combinator.Node.SanityCheck` in `Ouroboros.Consensus.HardFork.Combinator.Node.SanityCheck` through the production entrypoint using old-era chain selection data influencing new-era preference; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Forecast windows and ledger views must not allow stale pre-transition context to validate post-transition blocks.
- Expected Cardano/Intersect impact: Potential High if an era-boundary, forecast, ledger-view, query, or network-version mismatch breaks cross-era consensus invariants for production nodes.
- Fast validation: Create a hard-fork combinator test with boundary-slot blocks and assert header era, body era, ledger view, and protocol state agree.
