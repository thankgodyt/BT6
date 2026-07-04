# Q1874: reordered rollbacks and forward headers in SomeHeaderInFutureCheck

## Question
Can an unprivileged attacker reach SomeHeaderInFutureCheck with reordered rollbacks and forward headers and peer message ordering, withheld block bodies, advertised points, node-to-node version choice, local client queries, and reconnect timing, then starve a valid competing chain without prohibited flood-style DoS in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client/InFutureCheck.hs / SomeHeaderInFutureCheck
- Entrypoint: Unprivileged node-to-node or node-to-client peer sends supported protocol messages, rollbacks, block bodies, queries, or object-diffusion data in adversarial order.
- Attacker controls: peer message ordering, withheld block bodies, advertised points, node-to-node version choice, local client queries, and reconnect timing.
- Exploit idea: Drive `SomeHeaderInFutureCheck` in `Ouroboros.Consensus.MiniProtocol.ChainSync.Client.InFutureCheck` through the production entrypoint using reordered rollbacks and forward headers; verify whether the path can starve a valid competing chain without prohibited flood-style DoS before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A peer withholding, duplicating, or reordering data must not starve processing of a valid competing chain.
- Expected Cardano/Intersect impact: Potential Medium if an unprivileged peer can cause repeated expensive consensus work with near-valid data without flood-style DoS.
- Fast validation: Add a ChainSync/BlockFetch integration test with withheld bodies and a complete competing chain.
