# Q1786: pre transition fragments delivered in interpretQuery

## Question
Can an unprivileged attacker reach interpretQuery' with pre-transition fragments delivered after post-transition blocks and pre-transition fragments, post-transition blocks, translation boundary, stale era context, query dispatch tags, and replay order, then starve a valid competing chain without prohibited flood-style DoS in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/EpochInfo.hs / interpretQuery'
- Entrypoint: Remote peer or normal block producer delivers blocks, headers, queries, or encoded messages around an era boundary through supported node protocols.
- Attacker controls: pre-transition fragments, post-transition blocks, translation boundary, stale era context, query dispatch tags, and replay order.
- Exploit idea: Drive `interpretQuery'` in `Ouroboros.Consensus.HardFork.History.EpochInfo` through the production entrypoint using pre-transition fragments delivered after post-transition blocks; verify whether the path can starve a valid competing chain without prohibited flood-style DoS before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Ledger translation across eras must preserve the consensus state required for chain selection and block validation.
- Expected Cardano/Intersect impact: Potential High if an era-boundary, forecast, ledger-view, query, or network-version mismatch breaks cross-era consensus invariants for production nodes.
- Fast validation: Create a hard-fork combinator test with boundary-slot blocks and assert header era, body era, ledger view, and protocol state agree.
