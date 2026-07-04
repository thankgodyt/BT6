# Q2064: pre transition fragments delivered in Ouroboros Consensus Shelley Node Common

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.Shelley.Node.Common with pre-transition fragments delivered after post-transition blocks and pre-transition fragments, post-transition blocks, translation boundary, stale era context, query dispatch tags, and replay order, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Node/Common.hs / Ouroboros.Consensus.Shelley.Node.Common
- Entrypoint: Remote peer or normal block producer delivers blocks, headers, queries, or encoded messages around an era boundary through supported node protocols.
- Attacker controls: pre-transition fragments, post-transition blocks, translation boundary, stale era context, query dispatch tags, and replay order.
- Exploit idea: Drive `Ouroboros.Consensus.Shelley.Node.Common` in `Ouroboros.Consensus.Shelley.Node.Common` through the production entrypoint using pre-transition fragments delivered after post-transition blocks; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Ledger translation across eras must preserve the consensus state required for chain selection and block validation.
- Expected Cardano/Intersect impact: Potential High if an era-boundary, forecast, ledger-view, query, or network-version mismatch breaks cross-era consensus invariants for production nodes.
- Fast validation: Create a hard-fork combinator test with boundary-slot blocks and assert header era, body era, ledger view, and protocol state agree.
