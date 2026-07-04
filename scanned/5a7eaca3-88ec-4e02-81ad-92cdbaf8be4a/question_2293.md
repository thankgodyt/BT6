# Q2293: headers for a preferred candidate whose bodies arrive late in liftSkip

## Question
Can an unprivileged attacker reach liftSkip with headers for a preferred candidate whose bodies arrive late and valid-looking headers, delayed or invalid block bodies, fork length, predecessor hashes, slot numbers, duplicate announcements, and arrival order, then reuse stale validation or ledger context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Protocol/ChainSel.hs / liftSkip
- Entrypoint: Remote peer sends adversarial but protocol-reachable ChainSync headers, BlockFetch bodies, duplicates, and rollbacks through normal node-to-node syncing.
- Attacker controls: valid-looking headers, delayed or invalid block bodies, fork length, predecessor hashes, slot numbers, duplicate announcements, and arrival order.
- Exploit idea: Drive `liftSkip` in `Ouroboros.Consensus.HardFork.Combinator.Protocol.ChainSel` through the production entrypoint using headers for a preferred candidate whose bodies arrive late; verify whether the path can reuse stale validation or ledger context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Honest nodes receiving the same valid chain data must eventually select the same best chain regardless of arrival order.
- Expected Cardano/Intersect impact: Potential Medium if an unprivileged peer can cause sustained consensus/storage resource exhaustion through protocol-valid or near-valid data without prohibited flood-style DoS.
- Fast validation: Build a rollback/replay property comparing restored ledger state against fresh replay from the immutable anchor.
