# Q168: the first block in fromPerasCertVoters

## Question
Can an unprivileged attacker reach fromPerasCertVoters with the first block after an era transition and era-boundary slot, block/header era tags, network version, serialized query tags, ledger-view forecast timing, and predecessor chain context, then cause honest nodes to select different tips in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Committee.hs / fromPerasCertVoters
- Entrypoint: Remote peer or normal block producer delivers blocks, headers, queries, or encoded messages around an era boundary through supported node protocols.
- Attacker controls: era-boundary slot, block/header era tags, network version, serialized query tags, ledger-view forecast timing, and predecessor chain context.
- Exploit idea: Drive `fromPerasCertVoters` in `Ouroboros.Consensus.Peras.Voting.Committee` through the production entrypoint using the first block after an era transition; verify whether the path can cause honest nodes to select different tips before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A block at an era boundary must be interpreted under exactly one era for header, body, ledger, forecast, and protocol validation.
- Expected Cardano/Intersect impact: Potential High if an era-boundary, forecast, ledger-view, query, or network-version mismatch breaks cross-era consensus invariants for production nodes.
- Fast validation: Create a hard-fork combinator test with boundary-slot blocks and assert header era, body era, ledger view, and protocol state agree.
