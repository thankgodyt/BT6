# Q1767: query currentness in getSameConfigValue

## Question
Can an unprivileged attacker reach getSameConfigValue with query-currentness around a transition point and pre-transition fragments, post-transition blocks, translation boundary, stale era context, query dispatch tags, and replay order, then confuse header/body, era, or storage context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Node.hs / getSameConfigValue
- Entrypoint: Remote peer or normal block producer delivers blocks, headers, queries, or encoded messages around an era boundary through supported node protocols.
- Attacker controls: pre-transition fragments, post-transition blocks, translation boundary, stale era context, query dispatch tags, and replay order.
- Exploit idea: Drive `getSameConfigValue` in `Ouroboros.Consensus.HardFork.Combinator.Node` through the production entrypoint using query-currentness around a transition point; verify whether the path can confuse header/body, era, or storage context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Ledger translation across eras must preserve the consensus state required for chain selection and block validation.
- Expected Cardano/Intersect impact: Potential Critical if a crafted boundary block causes honest nodes to disagree on block validity or accept invalid state.
- Fast validation: Replay the same multi-era chain live and from persisted storage and compare hard-fork summary, selected tip, and ledger state hash.
