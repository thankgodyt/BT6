# Q1206: reordered rollbacks and forward headers in ExitFailure

## Question
Can an unprivileged attacker reach ExitFailure with reordered rollbacks and forward headers and peer message ordering, withheld block bodies, advertised points, node-to-node version choice, local client queries, and reconnect timing, then confuse header/body, era, or storage context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/Exit.hs / ExitFailure
- Entrypoint: Unprivileged node-to-node or node-to-client peer sends supported protocol messages, rollbacks, block bodies, queries, or object-diffusion data in adversarial order.
- Attacker controls: peer message ordering, withheld block bodies, advertised points, node-to-node version choice, local client queries, and reconnect timing.
- Exploit idea: Drive `ExitFailure` in `Ouroboros.Consensus.Node.Exit` through the production entrypoint using reordered rollbacks and forward headers; verify whether the path can confuse header/body, era, or storage context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A peer withholding, duplicating, or reordering data must not starve processing of a valid competing chain.
- Expected Cardano/Intersect impact: Potential High if adversarial peer scheduling makes honest nodes prefer different chains or starves valid block processing.
- Fast validation: Create an io-sim network with malicious and honest peers delivering headers, blocks, rollbacks, and disconnects in adversarial order.
