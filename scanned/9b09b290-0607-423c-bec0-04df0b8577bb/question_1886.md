# Q1886: supported version negotiation omitting expected fields in estimateBlockSize

## Question
Can an unprivileged attacker reach estimateBlockSize with supported version negotiation omitting expected fields and peer message ordering, withheld block bodies, advertised points, node-to-node version choice, local client queries, and reconnect timing, then confuse header/body, era, or storage context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Node/Run.hs / estimateBlockSize
- Entrypoint: Unprivileged node-to-node or node-to-client peer sends supported protocol messages, rollbacks, block bodies, queries, or object-diffusion data in adversarial order.
- Attacker controls: peer message ordering, withheld block bodies, advertised points, node-to-node version choice, local client queries, and reconnect timing.
- Exploit idea: Drive `estimateBlockSize` in `Ouroboros.Consensus.Node.Run` through the production entrypoint using supported version negotiation omitting expected fields; verify whether the path can confuse header/body, era, or storage context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A peer withholding, duplicating, or reordering data must not starve processing of a valid competing chain.
- Expected Cardano/Intersect impact: Potential Medium if an unprivileged peer can cause repeated expensive consensus work with near-valid data without flood-style DoS.
- Fast validation: Add a ChainSync/BlockFetch integration test with withheld bodies and a complete competing chain.
