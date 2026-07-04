# Q2525: reordered rollbacks and forward headers in findIntersection

## Question
Can an unprivileged attacker reach findIntersection with reordered rollbacks and forward headers and peer message ordering, withheld block bodies, advertised points, node-to-node version choice, local client queries, and reconnect timing, then confuse header/body, era, or storage context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs / findIntersection
- Entrypoint: Unprivileged node-to-node or node-to-client peer sends supported protocol messages, rollbacks, block bodies, queries, or object-diffusion data in adversarial order.
- Attacker controls: peer message ordering, withheld block bodies, advertised points, node-to-node version choice, local client queries, and reconnect timing.
- Exploit idea: Drive `findIntersection` in `Ouroboros.Consensus.MiniProtocol.ChainSync.Client` through the production entrypoint using reordered rollbacks and forward headers; verify whether the path can confuse header/body, era, or storage context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A peer withholding, duplicating, or reordering data must not starve processing of a valid competing chain.
- Expected Cardano/Intersect impact: Potential Medium if an unprivileged peer can cause repeated expensive consensus work with near-valid data without flood-style DoS.
- Fast validation: Add a ChainSync/BlockFetch integration test with withheld bodies and a complete competing chain.
