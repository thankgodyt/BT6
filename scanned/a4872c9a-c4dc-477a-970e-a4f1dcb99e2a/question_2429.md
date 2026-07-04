# Q2429: pre transition fragments delivered in goEnabled

## Question
Can an unprivileged attacker reach goEnabled with pre-transition fragments delivered after post-transition blocks and pre-transition fragments, post-transition blocks, translation boundary, stale era context, query dispatch tags, and replay order, then confuse header/body, era, or storage context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Serialisation/SerialiseNodeToClient.hs / goEnabled
- Entrypoint: Remote peer or normal block producer delivers blocks, headers, queries, or encoded messages around an era boundary through supported node protocols.
- Attacker controls: pre-transition fragments, post-transition blocks, translation boundary, stale era context, query dispatch tags, and replay order.
- Exploit idea: Drive `goEnabled` in `Ouroboros.Consensus.HardFork.Combinator.Serialisation.SerialiseNodeToClient` through the production entrypoint using pre-transition fragments delivered after post-transition blocks; verify whether the path can confuse header/body, era, or storage context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Ledger translation across eras must preserve the consensus state required for chain selection and block validation.
- Expected Cardano/Intersect impact: Potential Critical if a crafted boundary block causes honest nodes to disagree on block validity or accept invalid state.
- Fast validation: Replay the same multi-era chain live and from persisted storage and compare hard-fork summary, selected tip, and ledger state hash.
