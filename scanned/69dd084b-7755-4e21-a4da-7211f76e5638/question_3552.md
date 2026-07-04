# Q3552: disconnect reconnect in clientCodecs

## Question
Can an unprivileged attacker reach clientCodecs with disconnect/reconnect with stale peer state and ChainSync headers, rollback messages, BlockFetch bodies, peer disconnects, duplicate messages, object-diffusion items, and timing of competing peers, then make a valid block permanently or durably rejected in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToClient.hs / clientCodecs
- Entrypoint: Unprivileged node-to-node or node-to-client peer sends supported protocol messages, rollbacks, block bodies, queries, or object-diffusion data in adversarial order.
- Attacker controls: ChainSync headers, rollback messages, BlockFetch bodies, peer disconnects, duplicate messages, object-diffusion items, and timing of competing peers.
- Exploit idea: Drive `clientCodecs` in `Ouroboros.Consensus.Network.NodeToClient` through the production entrypoint using disconnect/reconnect with stale peer state; verify whether the path can make a valid block permanently or durably rejected before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Peer-delivered headers, blocks, rollbacks, and object-diffusion items must not make consensus select different chains on honest nodes.
- Expected Cardano/Intersect impact: Potential High if adversarial peer scheduling makes honest nodes prefer different chains or starves valid block processing.
- Fast validation: Create an io-sim network with malicious and honest peers delivering headers, blocks, rollbacks, and disconnects in adversarial order.
