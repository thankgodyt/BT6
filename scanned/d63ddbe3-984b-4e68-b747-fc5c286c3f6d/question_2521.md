# Q2521: supported version negotiation omitting expected fields in BlockConfig

## Question
Can an unprivileged attacker reach BlockConfig with supported version negotiation omitting expected fields and peer message ordering, withheld block bodies, advertised points, node-to-node version choice, local client queries, and reconnect timing, then starve a valid competing chain without prohibited flood-style DoS in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsDiffusionPipelining.hs / BlockConfig
- Entrypoint: Unprivileged node-to-node or node-to-client peer sends supported protocol messages, rollbacks, block bodies, queries, or object-diffusion data in adversarial order.
- Attacker controls: peer message ordering, withheld block bodies, advertised points, node-to-node version choice, local client queries, and reconnect timing.
- Exploit idea: Drive `BlockConfig` in `Ouroboros.Consensus.Block.SupportsDiffusionPipelining` through the production entrypoint using supported version negotiation omitting expected fields; verify whether the path can starve a valid competing chain without prohibited flood-style DoS before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A peer withholding, duplicating, or reordering data must not starve processing of a valid competing chain.
- Expected Cardano/Intersect impact: Potential High if adversarial peer scheduling makes honest nodes prefer different chains or starves valid block processing.
- Fast validation: Create an io-sim network with malicious and honest peers delivering headers, blocks, rollbacks, and disconnects in adversarial order.
