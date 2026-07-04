# Q593: queries treated as current in nodeToClientVersionToQueryVersion

## Question
Can an unprivileged attacker reach nodeToClientVersionToQueryVersion with queries treated as current after chain selection changes and ledger tables, diffs, mempool transactions, snapshot selection, state-query target, and block validation timing, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Ledger/Query/Version.hs / nodeToClientVersionToQueryVersion
- Entrypoint: Remote peer provides blocks/transactions that drive consensus ledger validation, replay, snapshots, or queries through normal node operation.
- Attacker controls: ledger tables, diffs, mempool transactions, snapshot selection, state-query target, and block validation timing.
- Exploit idea: Drive `nodeToClientVersionToQueryVersion` in `Ouroboros.Consensus.Ledger.Query.Version` through the production entrypoint using queries treated as current after chain selection changes; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A query or inspection path must not expose or use stale ledger state in a way that affects validation or block production.
- Expected Cardano/Intersect impact: Potential High if snapshot/replay restores a ledger state inconsistent with the selected chain.
- Fast validation: Construct block-body transaction ordering tests and compare mempool acceptance against block application.
