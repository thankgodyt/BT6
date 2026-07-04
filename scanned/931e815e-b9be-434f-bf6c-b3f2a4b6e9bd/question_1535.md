# Q1535: future headers queued until slot becomes current in returnPolicy

## Question
Can an unprivileged attacker reach returnPolicy with future headers queued until slot becomes current and normal adversarial network scheduling, delayed data, replayed announcements, fork delivery order, and diffusion-to-consensus callback timing, then starve a valid competing chain without prohibited flood-style DoS in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/ExitPolicy.hs / returnPolicy
- Entrypoint: Unprivileged node-to-node or node-to-client peer sends supported protocol messages, rollbacks, block bodies, queries, or object-diffusion data in adversarial order.
- Attacker controls: normal adversarial network scheduling, delayed data, replayed announcements, fork delivery order, and diffusion-to-consensus callback timing.
- Exploit idea: Drive `returnPolicy` in `Ouroboros.Consensus.Node.ExitPolicy` through the production entrypoint using future headers queued until slot becomes current; verify whether the path can starve a valid competing chain without prohibited flood-style DoS before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Disconnect/reconnect and Genesis sync transitions must not leave stale peer state that affects chain selection.
- Expected Cardano/Intersect impact: Potential Medium if a public node API or miniprotocol path exposes sensitive consensus state or weakens validation assumptions.
- Fast validation: Fuzz node-to-node messages and version negotiation while measuring known-invalid deduplication before expensive validation.
