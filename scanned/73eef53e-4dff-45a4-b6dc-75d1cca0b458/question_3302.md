# Q3302: reordered rollbacks and forward headers in returnPolicy

## Question
Can an unprivileged attacker reach returnPolicy with reordered rollbacks and forward headers and peer message ordering, withheld block bodies, advertised points, node-to-node version choice, local client queries, and reconnect timing, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/ExitPolicy.hs / returnPolicy
- Entrypoint: Unprivileged node-to-node or node-to-client peer sends supported protocol messages, rollbacks, block bodies, queries, or object-diffusion data in adversarial order.
- Attacker controls: peer message ordering, withheld block bodies, advertised points, node-to-node version choice, local client queries, and reconnect timing.
- Exploit idea: Drive `returnPolicy` in `Ouroboros.Consensus.Node.ExitPolicy` through the production entrypoint using reordered rollbacks and forward headers; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A peer withholding, duplicating, or reordering data must not starve processing of a valid competing chain.
- Expected Cardano/Intersect impact: Potential Medium if a public node API or miniprotocol path exposes sensitive consensus state or weakens validation assumptions.
- Fast validation: Fuzz node-to-node messages and version negotiation while measuring known-invalid deduplication before expensive validation.
