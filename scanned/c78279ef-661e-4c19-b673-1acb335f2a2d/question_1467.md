# Q1467: old era chain selection data influencing new era preference in makePerasCertPo

## Question
Can an unprivileged attacker reach makePerasCertPoolWriterFromChainDB with old-era chain selection data influencing new-era preference and transition ledger state, protocol parameter translation, forecast window, current-era tip, and historical summary reconstruction inputs, then confuse header/body, era, or storage context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs / makePerasCertPoolWriterFromChainDB
- Entrypoint: Remote peer or normal block producer delivers blocks, headers, queries, or encoded messages around an era boundary through supported node protocols.
- Attacker controls: transition ledger state, protocol parameter translation, forecast window, current-era tip, and historical summary reconstruction inputs.
- Exploit idea: Drive `makePerasCertPoolWriterFromChainDB` in `Ouroboros.Consensus.MiniProtocol.ObjectDiffusion.ObjectPool.PerasCert` through the production entrypoint using old-era chain selection data influencing new-era preference; verify whether the path can confuse header/body, era, or storage context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Forecast windows and ledger views must not allow stale pre-transition context to validate post-transition blocks.
- Expected Cardano/Intersect impact: Potential High if an era-boundary, forecast, ledger-view, query, or network-version mismatch breaks cross-era consensus invariants for production nodes.
- Fast validation: Create a hard-fork combinator test with boundary-slot blocks and assert header era, body era, ledger view, and protocol state agree.
