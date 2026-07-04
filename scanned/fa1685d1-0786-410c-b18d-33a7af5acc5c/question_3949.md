# Q3949: query currentness in candidates

## Question
Can an unprivileged attacker reach candidates with query-currentness around a transition point and pre-transition fragments, post-transition blocks, translation boundary, stale era context, query dispatch tags, and replay order, then confuse header/body, era, or storage context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-cardano/src/byron/Ouroboros/Consensus/Byron/Ledger/Inspect.hs / candidates
- Entrypoint: Remote peer or normal block producer delivers blocks, headers, queries, or encoded messages around an era boundary through supported node protocols.
- Attacker controls: pre-transition fragments, post-transition blocks, translation boundary, stale era context, query dispatch tags, and replay order.
- Exploit idea: Drive `candidates` in `Ouroboros.Consensus.Byron.Ledger.Inspect` through the production entrypoint using query-currentness around a transition point; verify whether the path can confuse header/body, era, or storage context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Ledger translation across eras must preserve the consensus state required for chain selection and block validation.
- Expected Cardano/Intersect impact: Potential High if replay or rollback across an era boundary makes honest nodes select different valid-chain tips.
- Fast validation: Fuzz node-to-node/node-to-client version tags and era indexes and assert mismatched payloads are rejected before validation.
