# Q781: old era chain selection data influencing new era preference in QueryAnytime

## Question
Can an unprivileged attacker reach QueryAnytime with old-era chain selection data influencing new-era preference and transition ledger state, protocol parameter translation, forecast window, current-era tip, and historical summary reconstruction inputs, then starve a valid competing chain without prohibited flood-style DoS in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Ledger/Query.hs / QueryAnytime
- Entrypoint: Remote peer or normal block producer delivers blocks, headers, queries, or encoded messages around an era boundary through supported node protocols.
- Attacker controls: transition ledger state, protocol parameter translation, forecast window, current-era tip, and historical summary reconstruction inputs.
- Exploit idea: Drive `QueryAnytime` in `Ouroboros.Consensus.HardFork.Combinator.Ledger.Query` through the production entrypoint using old-era chain selection data influencing new-era preference; verify whether the path can starve a valid competing chain without prohibited flood-style DoS before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Forecast windows and ledger views must not allow stale pre-transition context to validate post-transition blocks.
- Expected Cardano/Intersect impact: Potential Critical if a crafted boundary block causes honest nodes to disagree on block validity or accept invalid state.
- Fast validation: Replay the same multi-era chain live and from persisted storage and compare hard-fork summary, selected tip, and ledger state hash.
